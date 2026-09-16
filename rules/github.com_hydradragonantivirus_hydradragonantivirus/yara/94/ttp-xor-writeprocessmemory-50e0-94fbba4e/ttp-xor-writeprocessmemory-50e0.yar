rule TTP_XOR_WriteProcessMemory_50e0 {
  strings:
    $key_50e0 = { 07 92 [2] 35 b0 [2] 33 85 [2] 1d 85 [2] 22 99 }

  condition:
    any of them
}