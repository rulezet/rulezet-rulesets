rule TTP_XOR_WriteProcessMemory_0716 {
  strings:
    $key_0716 = { 50 64 [2] 62 46 [2] 64 73 [2] 4a 73 [2] 75 6f }

  condition:
    any of them
}