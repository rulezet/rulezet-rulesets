rule TTP_XOR_WriteProcessMemory_5184 {
  strings:
    $key_5184 = { 06 f6 [2] 34 d4 [2] 32 e1 [2] 1c e1 [2] 23 fd }

  condition:
    any of them
}