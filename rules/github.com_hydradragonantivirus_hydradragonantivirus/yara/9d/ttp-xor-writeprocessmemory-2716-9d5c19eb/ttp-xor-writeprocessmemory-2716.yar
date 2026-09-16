rule TTP_XOR_WriteProcessMemory_2716 {
  strings:
    $key_2716 = { 70 64 [2] 42 46 [2] 44 73 [2] 6a 73 [2] 55 6f }

  condition:
    any of them
}