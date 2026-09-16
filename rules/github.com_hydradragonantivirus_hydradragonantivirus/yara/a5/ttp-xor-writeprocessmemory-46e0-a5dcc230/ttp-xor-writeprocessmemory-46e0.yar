rule TTP_XOR_WriteProcessMemory_46e0 {
  strings:
    $key_46e0 = { 11 92 [2] 23 b0 [2] 25 85 [2] 0b 85 [2] 34 99 }

  condition:
    any of them
}