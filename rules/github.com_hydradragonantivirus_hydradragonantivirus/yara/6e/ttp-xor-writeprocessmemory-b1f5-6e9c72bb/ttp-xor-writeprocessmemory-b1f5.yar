rule TTP_XOR_WriteProcessMemory_b1f5 {
  strings:
    $key_b1f5 = { e6 87 [2] d4 a5 [2] d2 90 [2] fc 90 [2] c3 8c }

  condition:
    any of them
}