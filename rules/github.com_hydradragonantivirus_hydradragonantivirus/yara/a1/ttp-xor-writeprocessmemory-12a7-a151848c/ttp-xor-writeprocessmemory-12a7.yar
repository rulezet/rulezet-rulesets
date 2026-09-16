rule TTP_XOR_WriteProcessMemory_12a7 {
  strings:
    $key_12a7 = { 45 d5 [2] 77 f7 [2] 71 c2 [2] 5f c2 [2] 60 de }

  condition:
    any of them
}