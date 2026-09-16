rule TTP_XOR_WriteProcessMemory_2096 {
  strings:
    $key_2096 = { 77 e4 [2] 45 c6 [2] 43 f3 [2] 6d f3 [2] 52 ef }

  condition:
    any of them
}