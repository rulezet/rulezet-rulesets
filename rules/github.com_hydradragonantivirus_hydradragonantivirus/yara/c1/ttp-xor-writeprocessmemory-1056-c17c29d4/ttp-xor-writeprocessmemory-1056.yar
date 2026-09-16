rule TTP_XOR_WriteProcessMemory_1056 {
  strings:
    $key_1056 = { 47 24 [2] 75 06 [2] 73 33 [2] 5d 33 [2] 62 2f }

  condition:
    any of them
}