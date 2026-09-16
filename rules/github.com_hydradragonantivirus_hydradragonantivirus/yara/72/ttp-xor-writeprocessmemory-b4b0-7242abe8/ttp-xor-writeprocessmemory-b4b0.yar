rule TTP_XOR_WriteProcessMemory_b4b0 {
  strings:
    $key_b4b0 = { e3 c2 [2] d1 e0 [2] d7 d5 [2] f9 d5 [2] c6 c9 }

  condition:
    any of them
}