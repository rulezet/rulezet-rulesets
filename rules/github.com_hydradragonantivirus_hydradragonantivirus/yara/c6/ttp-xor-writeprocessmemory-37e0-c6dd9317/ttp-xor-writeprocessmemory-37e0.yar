rule TTP_XOR_WriteProcessMemory_37e0 {
  strings:
    $key_37e0 = { 60 92 [2] 52 b0 [2] 54 85 [2] 7a 85 [2] 45 99 }

  condition:
    any of them
}