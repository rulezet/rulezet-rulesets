rule TTP_XOR_WriteProcessMemory_b746 {
  strings:
    $key_b746 = { e0 34 [2] d2 16 [2] d4 23 [2] fa 23 [2] c5 3f }

  condition:
    any of them
}