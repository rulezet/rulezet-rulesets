rule TTP_XOR_WriteProcessMemory_b1f2 {
  strings:
    $key_b1f2 = { e6 80 [2] d4 a2 [2] d2 97 [2] fc 97 [2] c3 8b }

  condition:
    any of them
}