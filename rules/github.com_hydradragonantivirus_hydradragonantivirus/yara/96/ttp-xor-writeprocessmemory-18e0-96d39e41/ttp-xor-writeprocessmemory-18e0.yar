rule TTP_XOR_WriteProcessMemory_18e0 {
  strings:
    $key_18e0 = { 4f 92 [2] 7d b0 [2] 7b 85 [2] 55 85 [2] 6a 99 }

  condition:
    any of them
}