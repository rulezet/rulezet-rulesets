rule TTP_XOR_WriteProcessMemory_5181 {
  strings:
    $key_5181 = { 06 f3 [2] 34 d1 [2] 32 e4 [2] 1c e4 [2] 23 f8 }

  condition:
    any of them
}