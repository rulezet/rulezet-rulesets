rule TTP_XOR_WriteProcessMemory_6196 {
  strings:
    $key_6196 = { 36 e4 [2] 04 c6 [2] 02 f3 [2] 2c f3 [2] 13 ef }

  condition:
    any of them
}