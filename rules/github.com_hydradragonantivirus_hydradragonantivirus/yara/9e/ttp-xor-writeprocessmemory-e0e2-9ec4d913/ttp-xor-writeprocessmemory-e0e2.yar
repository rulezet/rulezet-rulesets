rule TTP_XOR_WriteProcessMemory_e0e2 {
  strings:
    $key_e0e2 = { b7 90 [2] 85 b2 [2] 83 87 [2] ad 87 [2] 92 9b }

  condition:
    any of them
}