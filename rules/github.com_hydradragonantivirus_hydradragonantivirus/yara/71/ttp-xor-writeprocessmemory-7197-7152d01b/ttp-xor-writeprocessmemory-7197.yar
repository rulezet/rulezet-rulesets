rule TTP_XOR_WriteProcessMemory_7197 {
  strings:
    $key_7197 = { 26 e5 [2] 14 c7 [2] 12 f2 [2] 3c f2 [2] 03 ee }

  condition:
    any of them
}