rule TTP_XOR_WriteProcessMemory_6fd9 {
  strings:
    $key_6fd9 = { 38 ab [2] 0a 89 [2] 0c bc [2] 22 bc [2] 1d a0 }

  condition:
    any of them
}