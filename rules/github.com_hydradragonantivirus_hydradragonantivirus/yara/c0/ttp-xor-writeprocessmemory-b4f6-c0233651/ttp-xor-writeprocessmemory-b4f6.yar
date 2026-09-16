rule TTP_XOR_WriteProcessMemory_b4f6 {
  strings:
    $key_b4f6 = { e3 84 [2] d1 a6 [2] d7 93 [2] f9 93 [2] c6 8f }

  condition:
    any of them
}