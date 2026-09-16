rule TTP_XOR_WriteProcessMemory_b5b0 {
  strings:
    $key_b5b0 = { e2 c2 [2] d0 e0 [2] d6 d5 [2] f8 d5 [2] c7 c9 }

  condition:
    any of them
}