rule TTP_XOR_WriteProcessMemory_4596 {
  strings:
    $key_4596 = { 12 e4 [2] 20 c6 [2] 26 f3 [2] 08 f3 [2] 37 ef }

  condition:
    any of them
}