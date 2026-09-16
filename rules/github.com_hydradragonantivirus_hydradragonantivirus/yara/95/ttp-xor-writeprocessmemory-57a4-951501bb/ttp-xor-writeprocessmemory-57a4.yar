rule TTP_XOR_WriteProcessMemory_57a4 {
  strings:
    $key_57a4 = { 00 d6 [2] 32 f4 [2] 34 c1 [2] 1a c1 [2] 25 dd }

  condition:
    any of them
}