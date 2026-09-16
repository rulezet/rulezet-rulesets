rule TTP_XOR_WriteProcessMemory_b2d2 {
  strings:
    $key_b2d2 = { e5 a0 [2] d7 82 [2] d1 b7 [2] ff b7 [2] c0 ab }

  condition:
    any of them
}