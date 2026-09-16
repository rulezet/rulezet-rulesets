rule TTP_XOR_WriteProcessMemory_6197 {
  strings:
    $key_6197 = { 36 e5 [2] 04 c7 [2] 02 f2 [2] 2c f2 [2] 13 ee }

  condition:
    any of them
}