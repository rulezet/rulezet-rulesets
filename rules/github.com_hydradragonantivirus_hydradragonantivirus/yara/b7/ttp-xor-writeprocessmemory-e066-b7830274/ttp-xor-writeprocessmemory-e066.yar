rule TTP_XOR_WriteProcessMemory_e066 {
  strings:
    $key_e066 = { b7 14 [2] 85 36 [2] 83 03 [2] ad 03 [2] 92 1f }

  condition:
    any of them
}