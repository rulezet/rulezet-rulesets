rule TTP_XOR_WriteProcessMemory_0d97 {
  strings:
    $key_0d97 = { 5a e5 [2] 68 c7 [2] 6e f2 [2] 40 f2 [2] 7f ee }

  condition:
    any of them
}