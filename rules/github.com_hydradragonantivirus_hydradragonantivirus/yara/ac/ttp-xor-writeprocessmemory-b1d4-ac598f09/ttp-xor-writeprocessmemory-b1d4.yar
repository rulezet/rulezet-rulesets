rule TTP_XOR_WriteProcessMemory_b1d4 {
  strings:
    $key_b1d4 = { e6 a6 [2] d4 84 [2] d2 b1 [2] fc b1 [2] c3 ad }

  condition:
    any of them
}