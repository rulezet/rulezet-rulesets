rule TTP_XOR_WriteProcessMemory_4cb1 {
  strings:
    $key_4cb1 = { 1b c3 [2] 29 e1 [2] 2f d4 [2] 01 d4 [2] 3e c8 }

  condition:
    any of them
}