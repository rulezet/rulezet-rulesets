rule TTP_XOR_WriteProcessMemory_b4d2 {
  strings:
    $key_b4d2 = { e3 a0 [2] d1 82 [2] d7 b7 [2] f9 b7 [2] c6 ab }

  condition:
    any of them
}