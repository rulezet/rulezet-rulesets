rule TTP_XOR_WriteProcessMemory_69b0 {
  strings:
    $key_69b0 = { 3e c2 [2] 0c e0 [2] 0a d5 [2] 24 d5 [2] 1b c9 }

  condition:
    any of them
}