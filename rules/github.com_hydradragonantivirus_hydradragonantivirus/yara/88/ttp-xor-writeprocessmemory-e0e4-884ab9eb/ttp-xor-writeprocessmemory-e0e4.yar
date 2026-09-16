rule TTP_XOR_WriteProcessMemory_e0e4 {
  strings:
    $key_e0e4 = { b7 96 [2] 85 b4 [2] 83 81 [2] ad 81 [2] 92 9d }

  condition:
    any of them
}