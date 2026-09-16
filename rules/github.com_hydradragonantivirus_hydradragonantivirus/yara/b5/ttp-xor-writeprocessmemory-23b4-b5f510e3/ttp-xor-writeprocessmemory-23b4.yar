rule TTP_XOR_WriteProcessMemory_23b4 {
  strings:
    $key_23b4 = { 74 c6 [2] 46 e4 [2] 40 d1 [2] 6e d1 [2] 51 cd }

  condition:
    any of them
}