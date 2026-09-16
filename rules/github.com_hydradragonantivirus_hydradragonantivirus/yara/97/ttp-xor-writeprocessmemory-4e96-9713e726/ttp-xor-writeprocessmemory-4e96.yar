rule TTP_XOR_WriteProcessMemory_4e96 {
  strings:
    $key_4e96 = { 19 e4 [2] 2b c6 [2] 2d f3 [2] 03 f3 [2] 3c ef }

  condition:
    any of them
}