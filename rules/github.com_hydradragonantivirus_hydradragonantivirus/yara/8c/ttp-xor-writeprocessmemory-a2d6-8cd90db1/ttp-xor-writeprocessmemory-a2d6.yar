rule TTP_XOR_WriteProcessMemory_a2d6 {
  strings:
    $key_a2d6 = { f5 a4 [2] c7 86 [2] c1 b3 [2] ef b3 [2] d0 af }

  condition:
    any of them
}