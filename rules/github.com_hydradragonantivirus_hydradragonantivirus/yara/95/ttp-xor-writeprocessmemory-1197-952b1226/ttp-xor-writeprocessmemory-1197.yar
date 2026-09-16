rule TTP_XOR_WriteProcessMemory_1197 {
  strings:
    $key_1197 = { 46 e5 [2] 74 c7 [2] 72 f2 [2] 5c f2 [2] 63 ee }

  condition:
    any of them
}