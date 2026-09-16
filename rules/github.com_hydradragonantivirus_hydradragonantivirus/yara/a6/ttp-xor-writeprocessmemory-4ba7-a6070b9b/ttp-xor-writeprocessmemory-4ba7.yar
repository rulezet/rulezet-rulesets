rule TTP_XOR_WriteProcessMemory_4ba7 {
  strings:
    $key_4ba7 = { 1c d5 [2] 2e f7 [2] 28 c2 [2] 06 c2 [2] 39 de }

  condition:
    any of them
}