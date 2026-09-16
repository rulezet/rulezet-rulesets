rule TTP_XOR_WriteProcessMemory_4d97 {
  strings:
    $key_4d97 = { 1a e5 [2] 28 c7 [2] 2e f2 [2] 00 f2 [2] 3f ee }

  condition:
    any of them
}