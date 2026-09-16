rule TTP_XOR_WriteProcessMemory_56d0 {
  strings:
    $key_56d0 = { 01 a2 [2] 33 80 [2] 35 b5 [2] 1b b5 [2] 24 a9 }

  condition:
    any of them
}