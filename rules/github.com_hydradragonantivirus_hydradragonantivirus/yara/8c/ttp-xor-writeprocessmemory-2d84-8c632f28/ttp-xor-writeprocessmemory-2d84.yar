rule TTP_XOR_WriteProcessMemory_2d84 {
  strings:
    $key_2d84 = { 7a f6 [2] 48 d4 [2] 4e e1 [2] 60 e1 [2] 5f fd }

  condition:
    any of them
}