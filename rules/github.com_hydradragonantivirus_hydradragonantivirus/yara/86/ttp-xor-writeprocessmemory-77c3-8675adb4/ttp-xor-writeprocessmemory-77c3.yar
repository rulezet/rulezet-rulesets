rule TTP_XOR_WriteProcessMemory_77c3 {
  strings:
    $key_77c3 = { 20 b1 [2] 12 93 [2] 14 a6 [2] 3a a6 [2] 05 ba }

  condition:
    any of them
}