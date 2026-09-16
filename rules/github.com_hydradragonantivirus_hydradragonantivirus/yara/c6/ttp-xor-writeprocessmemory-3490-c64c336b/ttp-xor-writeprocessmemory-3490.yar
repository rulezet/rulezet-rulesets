rule TTP_XOR_WriteProcessMemory_3490 {
  strings:
    $key_3490 = { 63 e2 [2] 51 c0 [2] 57 f5 [2] 79 f5 [2] 46 e9 }

  condition:
    any of them
}