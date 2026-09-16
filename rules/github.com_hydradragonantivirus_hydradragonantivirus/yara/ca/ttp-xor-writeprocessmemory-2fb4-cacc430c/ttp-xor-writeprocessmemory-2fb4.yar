rule TTP_XOR_WriteProcessMemory_2fb4 {
  strings:
    $key_2fb4 = { 78 c6 [2] 4a e4 [2] 4c d1 [2] 62 d1 [2] 5d cd }

  condition:
    any of them
}