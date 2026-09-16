rule TTP_XOR_WriteProcessMemory_2980 {
  strings:
    $key_2980 = { 7e f2 [2] 4c d0 [2] 4a e5 [2] 64 e5 [2] 5b f9 }

  condition:
    any of them
}