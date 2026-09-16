rule TTP_XOR_WriteProcessMemory_3b16 {
  strings:
    $key_3b16 = { 6c 64 [2] 5e 46 [2] 58 73 [2] 76 73 [2] 49 6f }

  condition:
    any of them
}