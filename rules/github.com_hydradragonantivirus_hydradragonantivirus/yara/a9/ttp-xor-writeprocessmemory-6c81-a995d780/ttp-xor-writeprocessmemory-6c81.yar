rule TTP_XOR_WriteProcessMemory_6c81 {
  strings:
    $key_6c81 = { 3b f3 [2] 09 d1 [2] 0f e4 [2] 21 e4 [2] 1e f8 }

  condition:
    any of them
}