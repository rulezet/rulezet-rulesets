rule TTP_XOR_WriteProcessMemory_b166 {
  strings:
    $key_b166 = { e6 14 [2] d4 36 [2] d2 03 [2] fc 03 [2] c3 1f }

  condition:
    any of them
}