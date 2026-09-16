rule TTP_XOR_WriteProcessMemory_e026 {
  strings:
    $key_e026 = { b7 54 [2] 85 76 [2] 83 43 [2] ad 43 [2] 92 5f }

  condition:
    any of them
}