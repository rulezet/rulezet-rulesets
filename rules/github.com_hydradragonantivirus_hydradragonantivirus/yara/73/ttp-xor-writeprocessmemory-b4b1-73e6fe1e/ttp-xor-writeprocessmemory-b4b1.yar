rule TTP_XOR_WriteProcessMemory_b4b1 {
  strings:
    $key_b4b1 = { e3 c3 [2] d1 e1 [2] d7 d4 [2] f9 d4 [2] c6 c8 }

  condition:
    any of them
}