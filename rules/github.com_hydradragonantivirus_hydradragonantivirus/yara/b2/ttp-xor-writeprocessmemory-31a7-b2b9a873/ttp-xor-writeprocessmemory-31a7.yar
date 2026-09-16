rule TTP_XOR_WriteProcessMemory_31a7 {
  strings:
    $key_31a7 = { 66 d5 [2] 54 f7 [2] 52 c2 [2] 7c c2 [2] 43 de }

  condition:
    any of them
}