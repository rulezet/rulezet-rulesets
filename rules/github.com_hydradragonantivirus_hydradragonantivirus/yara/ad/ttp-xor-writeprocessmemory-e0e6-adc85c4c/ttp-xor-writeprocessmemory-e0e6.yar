rule TTP_XOR_WriteProcessMemory_e0e6 {
  strings:
    $key_e0e6 = { b7 94 [2] 85 b6 [2] 83 83 [2] ad 83 [2] 92 9f }

  condition:
    any of them
}