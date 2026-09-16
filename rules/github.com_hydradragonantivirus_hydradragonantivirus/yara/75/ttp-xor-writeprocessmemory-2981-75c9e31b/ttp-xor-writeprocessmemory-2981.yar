rule TTP_XOR_WriteProcessMemory_2981 {
  strings:
    $key_2981 = { 7e f3 [2] 4c d1 [2] 4a e4 [2] 64 e4 [2] 5b f8 }

  condition:
    any of them
}