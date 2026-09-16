rule TTP_XOR_WriteProcessMemory_b5b1 {
  strings:
    $key_b5b1 = { e2 c3 [2] d0 e1 [2] d6 d4 [2] f8 d4 [2] c7 c8 }

  condition:
    any of them
}