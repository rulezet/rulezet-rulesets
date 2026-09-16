rule TTP_XOR_WriteProcessMemory_5c16 {
  strings:
    $key_5c16 = { 0b 64 [2] 39 46 [2] 3f 73 [2] 11 73 [2] 2e 6f }

  condition:
    any of them
}