rule TTP_XOR_WriteProcessMemory_0181 {
  strings:
    $key_0181 = { 56 f3 [2] 64 d1 [2] 62 e4 [2] 4c e4 [2] 73 f8 }

  condition:
    any of them
}