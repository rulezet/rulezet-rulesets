rule TTP_XOR_WriteProcessMemory_6d97 {
  strings:
    $key_6d97 = { 3a e5 [2] 08 c7 [2] 0e f2 [2] 20 f2 [2] 1f ee }

  condition:
    any of them
}