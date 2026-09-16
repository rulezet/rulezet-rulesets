rule TTP_XOR_WriteProcessMemory_20e0 {
  strings:
    $key_20e0 = { 77 92 [2] 45 b0 [2] 43 85 [2] 6d 85 [2] 52 99 }

  condition:
    any of them
}