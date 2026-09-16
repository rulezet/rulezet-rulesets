rule TTP_XOR_WriteProcessMemory_1090 {
  strings:
    $key_1090 = { 47 e2 [2] 75 c0 [2] 73 f5 [2] 5d f5 [2] 62 e9 }

  condition:
    any of them
}