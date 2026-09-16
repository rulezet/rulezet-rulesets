rule TTP_XOR_WriteProcessMemory_73e0 {
  strings:
    $key_73e0 = { 24 92 [2] 16 b0 [2] 10 85 [2] 3e 85 [2] 01 99 }

  condition:
    any of them
}