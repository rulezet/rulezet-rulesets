rule TTP_XOR_WriteProcessMemory_5596 {
  strings:
    $key_5596 = { 02 e4 [2] 30 c6 [2] 36 f3 [2] 18 f3 [2] 27 ef }

  condition:
    any of them
}