rule TTP_XOR_WriteProcessMemory_7796 {
  strings:
    $key_7796 = { 20 e4 [2] 12 c6 [2] 14 f3 [2] 3a f3 [2] 05 ef }

  condition:
    any of them
}