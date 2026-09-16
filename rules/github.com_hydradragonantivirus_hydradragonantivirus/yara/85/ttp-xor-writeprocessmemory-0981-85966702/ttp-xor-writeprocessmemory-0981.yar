rule TTP_XOR_WriteProcessMemory_0981 {
  strings:
    $key_0981 = { 5e f3 [2] 6c d1 [2] 6a e4 [2] 44 e4 [2] 7b f8 }

  condition:
    any of them
}