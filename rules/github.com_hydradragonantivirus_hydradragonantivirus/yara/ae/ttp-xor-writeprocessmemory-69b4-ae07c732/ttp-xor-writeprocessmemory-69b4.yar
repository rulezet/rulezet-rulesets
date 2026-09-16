rule TTP_XOR_WriteProcessMemory_69b4 {
  strings:
    $key_69b4 = { 3e c6 [2] 0c e4 [2] 0a d1 [2] 24 d1 [2] 1b cd }

  condition:
    any of them
}