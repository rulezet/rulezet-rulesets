rule TTP_XOR_WriteProcessMemory_50a4 {
  strings:
    $key_50a4 = { 07 d6 [2] 35 f4 [2] 33 c1 [2] 1d c1 [2] 22 dd }

  condition:
    any of them
}