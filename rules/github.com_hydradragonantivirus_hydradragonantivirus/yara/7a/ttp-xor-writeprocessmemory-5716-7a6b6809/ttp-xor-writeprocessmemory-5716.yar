rule TTP_XOR_WriteProcessMemory_5716 {
  strings:
    $key_5716 = { 00 64 [2] 32 46 [2] 34 73 [2] 1a 73 [2] 25 6f }

  condition:
    any of them
}