rule TTP_XOR_WriteProcessMemory_5516 {
  strings:
    $key_5516 = { 02 64 [2] 30 46 [2] 36 73 [2] 18 73 [2] 27 6f }

  condition:
    any of them
}