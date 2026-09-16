rule TTP_XOR_WriteProcessMemory_e046 {
  strings:
    $key_e046 = { b7 34 [2] 85 16 [2] 83 23 [2] ad 23 [2] 92 3f }

  condition:
    any of them
}