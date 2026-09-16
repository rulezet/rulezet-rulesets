rule TTP_XOR_WriteProcessMemory_47c3 {
  strings:
    $key_47c3 = { 10 b1 [2] 22 93 [2] 24 a6 [2] 0a a6 [2] 35 ba }

  condition:
    any of them
}