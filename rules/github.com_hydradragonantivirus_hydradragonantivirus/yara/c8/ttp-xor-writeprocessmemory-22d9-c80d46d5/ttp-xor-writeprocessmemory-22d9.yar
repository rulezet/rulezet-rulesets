rule TTP_XOR_WriteProcessMemory_22d9 {
  strings:
    $key_22d9 = { 75 ab [2] 47 89 [2] 41 bc [2] 6f bc [2] 50 a0 }

  condition:
    any of them
}