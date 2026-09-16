rule TTP_XOR_WriteProcessMemory_e054 {
  strings:
    $key_e054 = { b7 26 [2] 85 04 [2] 83 31 [2] ad 31 [2] 92 2d }

  condition:
    any of them
}