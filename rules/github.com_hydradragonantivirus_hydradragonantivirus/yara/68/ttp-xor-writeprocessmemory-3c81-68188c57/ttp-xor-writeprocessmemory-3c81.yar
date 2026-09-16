rule TTP_XOR_WriteProcessMemory_3c81 {
  strings:
    $key_3c81 = { 6b f3 [2] 59 d1 [2] 5f e4 [2] 71 e4 [2] 4e f8 }

  condition:
    any of them
}