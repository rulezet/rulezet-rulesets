rule TTP_XOR_WriteProcessMemory_1981 {
  strings:
    $key_1981 = { 4e f3 [2] 7c d1 [2] 7a e4 [2] 54 e4 [2] 6b f8 }

  condition:
    any of them
}