rule TTP_XOR_WriteProcessMemory_b5d2 {
  strings:
    $key_b5d2 = { e2 a0 [2] d0 82 [2] d6 b7 [2] f8 b7 [2] c7 ab }

  condition:
    any of them
}