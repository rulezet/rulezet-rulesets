rule TTP_XOR_WriteProcessMemory_4ae0 {
  strings:
    $key_4ae0 = { 1d 92 [2] 2f b0 [2] 29 85 [2] 07 85 [2] 38 99 }

  condition:
    any of them
}