rule TTP_XOR_WriteProcessMemory_0b16 {
  strings:
    $key_0b16 = { 5c 64 [2] 6e 46 [2] 68 73 [2] 46 73 [2] 79 6f }

  condition:
    any of them
}