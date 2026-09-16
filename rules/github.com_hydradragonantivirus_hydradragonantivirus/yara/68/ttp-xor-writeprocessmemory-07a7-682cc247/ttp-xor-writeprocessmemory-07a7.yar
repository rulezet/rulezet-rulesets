rule TTP_XOR_WriteProcessMemory_07a7 {
  strings:
    $key_07a7 = { 50 d5 [2] 62 f7 [2] 64 c2 [2] 4a c2 [2] 75 de }

  condition:
    any of them
}