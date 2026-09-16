rule TTP_XOR_WriteProcessMemory_26a7 {
  strings:
    $key_26a7 = { 71 d5 [2] 43 f7 [2] 45 c2 [2] 6b c2 [2] 54 de }

  condition:
    any of them
}