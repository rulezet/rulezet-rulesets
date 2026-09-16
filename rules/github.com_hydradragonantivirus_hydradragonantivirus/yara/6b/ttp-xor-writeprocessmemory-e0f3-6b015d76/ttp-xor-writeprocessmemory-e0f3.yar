rule TTP_XOR_WriteProcessMemory_e0f3 {
  strings:
    $key_e0f3 = { b7 81 [2] 85 a3 [2] 83 96 [2] ad 96 [2] 92 8a }

  condition:
    any of them
}