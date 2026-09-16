rule TTP_XOR_WriteProcessMemory_e044 {
  strings:
    $key_e044 = { b7 36 [2] 85 14 [2] 83 21 [2] ad 21 [2] 92 3d }

  condition:
    any of them
}