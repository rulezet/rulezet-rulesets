rule TTP_XOR_WriteProcessMemory_5032 {
  strings:
    $key_5032 = { 07 40 [2] 35 62 [2] 33 57 [2] 1d 57 [2] 22 4b }

  condition:
    any of them
}