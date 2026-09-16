rule TTP_XOR_WriteProcessMemory_5fd9 {
  strings:
    $key_5fd9 = { 08 ab [2] 3a 89 [2] 3c bc [2] 12 bc [2] 2d a0 }

  condition:
    any of them
}