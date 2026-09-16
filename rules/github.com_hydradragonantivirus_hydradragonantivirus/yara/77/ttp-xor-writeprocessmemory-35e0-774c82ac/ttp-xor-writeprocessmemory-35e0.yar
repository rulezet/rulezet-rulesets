rule TTP_XOR_WriteProcessMemory_35e0 {
  strings:
    $key_35e0 = { 62 92 [2] 50 b0 [2] 56 85 [2] 78 85 [2] 47 99 }

  condition:
    any of them
}