rule TTP_XOR_WriteProcessMemory_e0e0 {
  strings:
    $key_e0e0 = { b7 92 [2] 85 b0 [2] 83 85 [2] ad 85 [2] 92 99 }

  condition:
    any of them
}