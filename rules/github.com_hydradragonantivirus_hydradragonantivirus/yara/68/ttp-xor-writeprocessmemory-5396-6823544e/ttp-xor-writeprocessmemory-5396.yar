rule TTP_XOR_WriteProcessMemory_5396 {
  strings:
    $key_5396 = { 04 e4 [2] 36 c6 [2] 30 f3 [2] 1e f3 [2] 21 ef }

  condition:
    any of them
}