rule TTP_XOR_WriteProcessMemory_4056 {
  strings:
    $key_4056 = { 17 24 [2] 25 06 [2] 23 33 [2] 0d 33 [2] 32 2f }

  condition:
    any of them
}