rule TTP_XOR_WriteProcessMemory_4981 {
  strings:
    $key_4981 = { 1e f3 [2] 2c d1 [2] 2a e4 [2] 04 e4 [2] 3b f8 }

  condition:
    any of them
}