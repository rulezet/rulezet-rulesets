rule TTP_XOR_WriteProcessMemory_b5e1 {
  strings:
    $key_b5e1 = { e2 93 [2] d0 b1 [2] d6 84 [2] f8 84 [2] c7 98 }

  condition:
    any of them
}