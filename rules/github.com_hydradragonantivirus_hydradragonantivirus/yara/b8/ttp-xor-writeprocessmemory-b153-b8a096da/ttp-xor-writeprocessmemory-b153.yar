rule TTP_XOR_WriteProcessMemory_b153 {
  strings:
    $key_b153 = { e6 21 [2] d4 03 [2] d2 36 [2] fc 36 [2] c3 2a }

  condition:
    any of them
}