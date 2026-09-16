rule TTP_XOR_WriteProcessMemory_35d9 {
  strings:
    $key_35d9 = { 62 ab [2] 50 89 [2] 56 bc [2] 78 bc [2] 47 a0 }

  condition:
    any of them
}