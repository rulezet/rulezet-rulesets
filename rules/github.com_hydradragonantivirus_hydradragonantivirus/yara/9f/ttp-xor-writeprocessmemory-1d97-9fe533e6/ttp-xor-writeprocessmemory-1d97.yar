rule TTP_XOR_WriteProcessMemory_1d97 {
  strings:
    $key_1d97 = { 4a e5 [2] 78 c7 [2] 7e f2 [2] 50 f2 [2] 6f ee }

  condition:
    any of them
}