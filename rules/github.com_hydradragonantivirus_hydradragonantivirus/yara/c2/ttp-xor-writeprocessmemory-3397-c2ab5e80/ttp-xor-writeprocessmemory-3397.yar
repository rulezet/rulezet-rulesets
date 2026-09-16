rule TTP_XOR_WriteProcessMemory_3397 {
  strings:
    $key_3397 = { 64 e5 [2] 56 c7 [2] 50 f2 [2] 7e f2 [2] 41 ee }

  condition:
    any of them
}