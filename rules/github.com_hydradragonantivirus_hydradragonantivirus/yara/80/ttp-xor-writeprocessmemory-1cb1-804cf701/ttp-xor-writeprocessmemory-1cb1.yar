rule TTP_XOR_WriteProcessMemory_1cb1 {
  strings:
    $key_1cb1 = { 4b c3 [2] 79 e1 [2] 7f d4 [2] 51 d4 [2] 6e c8 }

  condition:
    any of them
}