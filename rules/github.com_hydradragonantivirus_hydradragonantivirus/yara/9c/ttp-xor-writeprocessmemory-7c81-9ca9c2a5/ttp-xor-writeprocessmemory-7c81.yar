rule TTP_XOR_WriteProcessMemory_7c81 {
  strings:
    $key_7c81 = { 2b f3 [2] 19 d1 [2] 1f e4 [2] 31 e4 [2] 0e f8 }

  condition:
    any of them
}