rule TTP_XOR_WriteProcessMemory_78a4 {
  strings:
    $key_78a4 = { 2f d6 [2] 1d f4 [2] 1b c1 [2] 35 c1 [2] 0a dd }

  condition:
    any of them
}