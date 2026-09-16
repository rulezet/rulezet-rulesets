rule TTP_XOR_WriteProcessMemory_b1e1 {
  strings:
    $key_b1e1 = { e6 93 [2] d4 b1 [2] d2 84 [2] fc 84 [2] c3 98 }

  condition:
    any of them
}