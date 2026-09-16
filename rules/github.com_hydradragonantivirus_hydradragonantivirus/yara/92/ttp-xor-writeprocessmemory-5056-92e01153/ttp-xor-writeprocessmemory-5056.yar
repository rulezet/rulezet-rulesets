rule TTP_XOR_WriteProcessMemory_5056 {
  strings:
    $key_5056 = { 07 24 [2] 35 06 [2] 33 33 [2] 1d 33 [2] 22 2f }

  condition:
    any of them
}