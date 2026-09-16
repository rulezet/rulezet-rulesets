rule TTP_XOR_WriteProcessMemory_13e0 {
  strings:
    $key_13e0 = { 44 92 [2] 76 b0 [2] 70 85 [2] 5e 85 [2] 61 99 }

  condition:
    any of them
}