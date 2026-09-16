rule TTP_XOR_WriteProcessMemory_7716 {
  strings:
    $key_7716 = { 20 64 [2] 12 46 [2] 14 73 [2] 3a 73 [2] 05 6f }

  condition:
    any of them
}