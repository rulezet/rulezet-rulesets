rule TTP_XOR_WriteProcessMemory_6392 {
  strings:
    $key_6392 = { 34 e0 [2] 06 c2 [2] 00 f7 [2] 2e f7 [2] 11 eb }

  condition:
    any of them
}