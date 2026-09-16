rule TTP_XOR_WriteProcessMemory_4116 {
  strings:
    $key_4116 = { 16 64 [2] 24 46 [2] 22 73 [2] 0c 73 [2] 33 6f }

  condition:
    any of them
}