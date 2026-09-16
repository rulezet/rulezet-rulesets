rule TTP_XOR_WriteProcessMemory_5496 {
  strings:
    $key_5496 = { 03 e4 [2] 31 c6 [2] 37 f3 [2] 19 f3 [2] 26 ef }

  condition:
    any of them
}