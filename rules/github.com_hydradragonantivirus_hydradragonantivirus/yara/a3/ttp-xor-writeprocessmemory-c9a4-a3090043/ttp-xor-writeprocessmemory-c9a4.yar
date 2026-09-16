rule TTP_XOR_WriteProcessMemory_c9a4 {
  strings:
    $key_c9a4 = { 9e d6 [2] ac f4 [2] aa c1 [2] 84 c1 [2] bb dd }

  condition:
    any of them
}