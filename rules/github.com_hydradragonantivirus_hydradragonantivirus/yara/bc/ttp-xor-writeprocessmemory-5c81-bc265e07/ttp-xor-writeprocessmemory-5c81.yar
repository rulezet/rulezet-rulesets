rule TTP_XOR_WriteProcessMemory_5c81 {
  strings:
    $key_5c81 = { 0b f3 [2] 39 d1 [2] 3f e4 [2] 11 e4 [2] 2e f8 }

  condition:
    any of them
}