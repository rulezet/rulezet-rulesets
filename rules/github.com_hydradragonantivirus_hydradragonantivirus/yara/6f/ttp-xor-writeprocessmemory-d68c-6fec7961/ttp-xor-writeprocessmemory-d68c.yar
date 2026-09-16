rule TTP_XOR_WriteProcessMemory_d68c {
  strings:
    $key_d68c = { 81 fe [2] b3 dc [2] b5 e9 [2] 9b e9 [2] a4 f5 }

  condition:
    any of them
}