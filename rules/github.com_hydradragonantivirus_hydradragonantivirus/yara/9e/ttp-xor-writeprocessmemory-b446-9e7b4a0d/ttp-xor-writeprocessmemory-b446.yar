rule TTP_XOR_WriteProcessMemory_b446 {
  strings:
    $key_b446 = { e3 34 [2] d1 16 [2] d7 23 [2] f9 23 [2] c6 3f }

  condition:
    any of them
}