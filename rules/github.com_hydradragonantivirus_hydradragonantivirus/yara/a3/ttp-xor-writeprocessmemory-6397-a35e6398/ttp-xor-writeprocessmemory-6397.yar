rule TTP_XOR_WriteProcessMemory_6397 {
  strings:
    $key_6397 = { 34 e5 [2] 06 c7 [2] 00 f2 [2] 2e f2 [2] 11 ee }

  condition:
    any of them
}