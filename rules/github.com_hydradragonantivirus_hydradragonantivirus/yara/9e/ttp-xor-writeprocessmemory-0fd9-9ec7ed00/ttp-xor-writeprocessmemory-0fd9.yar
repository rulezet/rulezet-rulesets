rule TTP_XOR_WriteProcessMemory_0fd9 {
  strings:
    $key_0fd9 = { 58 ab [2] 6a 89 [2] 6c bc [2] 42 bc [2] 7d a0 }

  condition:
    any of them
}