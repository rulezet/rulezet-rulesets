rule TTP_XOR_WriteProcessMemory_ea20 {
  strings:
    $key_ea20 = { bd 52 [2] 8f 70 [2] 89 45 [2] a7 45 [2] 98 59 }

  condition:
    any of them
}