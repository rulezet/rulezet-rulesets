rule TTP_XOR_WriteProcessMemory_6396 {
  strings:
    $key_6396 = { 34 e4 [2] 06 c6 [2] 00 f3 [2] 2e f3 [2] 11 ef }

  condition:
    any of them
}