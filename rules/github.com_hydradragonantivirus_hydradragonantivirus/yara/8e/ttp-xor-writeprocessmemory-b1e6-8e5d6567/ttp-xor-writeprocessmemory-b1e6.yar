rule TTP_XOR_WriteProcessMemory_b1e6 {
  strings:
    $key_b1e6 = { e6 94 [2] d4 b6 [2] d2 83 [2] fc 83 [2] c3 9f }

  condition:
    any of them
}