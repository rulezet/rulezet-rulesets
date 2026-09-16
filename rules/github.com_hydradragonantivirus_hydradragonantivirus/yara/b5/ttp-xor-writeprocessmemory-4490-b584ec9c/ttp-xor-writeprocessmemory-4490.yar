rule TTP_XOR_WriteProcessMemory_4490 {
  strings:
    $key_4490 = { 13 e2 [2] 21 c0 [2] 27 f5 [2] 09 f5 [2] 36 e9 }

  condition:
    any of them
}