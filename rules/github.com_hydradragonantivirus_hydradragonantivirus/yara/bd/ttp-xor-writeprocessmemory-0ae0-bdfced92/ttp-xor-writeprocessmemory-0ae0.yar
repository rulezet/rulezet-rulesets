rule TTP_XOR_WriteProcessMemory_0ae0 {
  strings:
    $key_0ae0 = { 5d 92 [2] 6f b0 [2] 69 85 [2] 47 85 [2] 78 99 }

  condition:
    any of them
}