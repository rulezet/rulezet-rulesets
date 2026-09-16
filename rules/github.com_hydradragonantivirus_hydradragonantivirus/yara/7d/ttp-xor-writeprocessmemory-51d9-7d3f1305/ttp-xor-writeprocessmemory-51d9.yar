rule TTP_XOR_WriteProcessMemory_51d9 {
  strings:
    $key_51d9 = { 06 ab [2] 34 89 [2] 32 bc [2] 1c bc [2] 23 a0 }

  condition:
    any of them
}