rule TTP_XOR_WriteProcessMemory_4316 {
  strings:
    $key_4316 = { 14 64 [2] 26 46 [2] 20 73 [2] 0e 73 [2] 31 6f }

  condition:
    any of them
}