rule TTP_XOR_WriteProcessMemory_25e0 {
  strings:
    $key_25e0 = { 72 92 [2] 40 b0 [2] 46 85 [2] 68 85 [2] 57 99 }

  condition:
    any of them
}