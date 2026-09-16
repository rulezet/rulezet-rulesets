rule TTP_XOR_WriteProcessMemory_1ab1 {
  strings:
    $key_1ab1 = { 4d c3 [2] 7f e1 [2] 79 d4 [2] 57 d4 [2] 68 c8 }

  condition:
    any of them
}