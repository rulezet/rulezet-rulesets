rule TTP_XOR_WriteProcessMemory_b116 {
  strings:
    $key_b116 = { e6 64 [2] d4 46 [2] d2 73 [2] fc 73 [2] c3 6f }

  condition:
    any of them
}