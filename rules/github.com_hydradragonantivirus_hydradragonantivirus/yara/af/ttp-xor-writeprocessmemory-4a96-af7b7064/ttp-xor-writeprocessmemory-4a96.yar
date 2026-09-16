rule TTP_XOR_WriteProcessMemory_4a96 {
  strings:
    $key_4a96 = { 1d e4 [2] 2f c6 [2] 29 f3 [2] 07 f3 [2] 38 ef }

  condition:
    any of them
}