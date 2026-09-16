rule TTP_XOR_WriteProcessMemory_b736 {
  strings:
    $key_b736 = { e0 44 [2] d2 66 [2] d4 53 [2] fa 53 [2] c5 4f }

  condition:
    any of them
}