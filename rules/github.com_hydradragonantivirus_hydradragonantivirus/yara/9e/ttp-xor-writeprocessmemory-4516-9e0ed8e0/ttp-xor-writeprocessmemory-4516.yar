rule TTP_XOR_WriteProcessMemory_4516 {
  strings:
    $key_4516 = { 12 64 [2] 20 46 [2] 26 73 [2] 08 73 [2] 37 6f }

  condition:
    any of them
}