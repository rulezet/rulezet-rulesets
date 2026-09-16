rule TTP_XOR_WriteProcessMemory_20a7 {
  strings:
    $key_20a7 = { 77 d5 [2] 45 f7 [2] 43 c2 [2] 6d c2 [2] 52 de }

  condition:
    any of them
}