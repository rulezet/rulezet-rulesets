rule TTP_XOR_WriteProcessMemory_b484 {
  strings:
    $key_b484 = { e3 f6 [2] d1 d4 [2] d7 e1 [2] f9 e1 [2] c6 fd }

  condition:
    any of them
}