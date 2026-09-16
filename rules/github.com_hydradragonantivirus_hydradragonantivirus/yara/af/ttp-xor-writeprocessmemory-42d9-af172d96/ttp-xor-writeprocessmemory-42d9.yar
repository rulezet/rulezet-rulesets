rule TTP_XOR_WriteProcessMemory_42d9 {
  strings:
    $key_42d9 = { 15 ab [2] 27 89 [2] 21 bc [2] 0f bc [2] 30 a0 }

  condition:
    any of them
}