rule TTP_XOR_WriteProcessMemory_56d1 {
  strings:
    $key_56d1 = { 01 a3 [2] 33 81 [2] 35 b4 [2] 1b b4 [2] 24 a8 }

  condition:
    any of them
}