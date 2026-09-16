rule TTP_XOR_WriteProcessMemory_b1d2 {
  strings:
    $key_b1d2 = { e6 a0 [2] d4 82 [2] d2 b7 [2] fc b7 [2] c3 ab }

  condition:
    any of them
}