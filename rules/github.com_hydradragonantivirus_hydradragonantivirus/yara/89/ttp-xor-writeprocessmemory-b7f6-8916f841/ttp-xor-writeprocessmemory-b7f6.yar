rule TTP_XOR_WriteProcessMemory_b7f6 {
  strings:
    $key_b7f6 = { e0 84 [2] d2 a6 [2] d4 93 [2] fa 93 [2] c5 8f }

  condition:
    any of them
}