rule TTP_XOR_WriteProcessMemory_67f6 {
  strings:
    $key_67f6 = { 30 84 [2] 02 a6 [2] 04 93 [2] 2a 93 [2] 15 8f }

  condition:
    any of them
}