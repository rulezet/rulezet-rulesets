rule TTP_XOR_WriteProcessMemory_e0f7 {
  strings:
    $key_e0f7 = { b7 85 [2] 85 a7 [2] 83 92 [2] ad 92 [2] 92 8e }

  condition:
    any of them
}