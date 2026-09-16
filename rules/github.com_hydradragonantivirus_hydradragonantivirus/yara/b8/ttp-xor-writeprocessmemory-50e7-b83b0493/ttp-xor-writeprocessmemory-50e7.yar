rule TTP_XOR_WriteProcessMemory_50e7 {
  strings:
    $key_50e7 = { 07 95 [2] 35 b7 [2] 33 82 [2] 1d 82 [2] 22 9e }

  condition:
    any of them
}