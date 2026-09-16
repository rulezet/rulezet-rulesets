rule TTP_XOR_WriteProcessMemory_e99d {
  strings:
    $key_e99d = { be ef [2] 8c cd [2] 8a f8 [2] a4 f8 [2] 9b e4 }

  condition:
    any of them
}