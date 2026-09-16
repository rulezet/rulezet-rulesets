rule TTP_XOR_WriteProcessMemory_11f0 {
  strings:
    $key_11f0 = { 46 82 [2] 74 a0 [2] 72 95 [2] 5c 95 [2] 63 89 }

  condition:
    any of them
}