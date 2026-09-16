rule TTP_XOR_WriteProcessMemory_50d9 {
  strings:
    $key_50d9 = { 07 ab [2] 35 89 [2] 33 bc [2] 1d bc [2] 22 a0 }

  condition:
    any of them
}