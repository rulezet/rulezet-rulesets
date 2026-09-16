rule TTP_XOR_WriteProcessMemory_1ab0 {
  strings:
    $key_1ab0 = { 4d c2 [2] 7f e0 [2] 79 d5 [2] 57 d5 [2] 68 c9 }

  condition:
    any of them
}