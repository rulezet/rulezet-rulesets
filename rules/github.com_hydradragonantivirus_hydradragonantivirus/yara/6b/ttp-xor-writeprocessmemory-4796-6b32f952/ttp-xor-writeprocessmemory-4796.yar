rule TTP_XOR_WriteProcessMemory_4796 {
  strings:
    $key_4796 = { 10 e4 [2] 22 c6 [2] 24 f3 [2] 0a f3 [2] 35 ef }

  condition:
    any of them
}