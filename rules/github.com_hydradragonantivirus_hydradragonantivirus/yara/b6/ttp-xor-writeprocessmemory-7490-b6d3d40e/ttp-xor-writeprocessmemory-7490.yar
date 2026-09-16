rule TTP_XOR_WriteProcessMemory_7490 {
  strings:
    $key_7490 = { 23 e2 [2] 11 c0 [2] 17 f5 [2] 39 f5 [2] 06 e9 }

  condition:
    any of them
}