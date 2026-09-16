rule TTP_XOR_WriteProcessMemory_e916 {
  strings:
    $key_e916 = { be 64 [2] 8c 46 [2] 8a 73 [2] a4 73 [2] 9b 6f }

  condition:
    any of them
}