rule TTP_XOR_WriteProcessMemory_41d9 {
  strings:
    $key_41d9 = { 16 ab [2] 24 89 [2] 22 bc [2] 0c bc [2] 33 a0 }

  condition:
    any of them
}