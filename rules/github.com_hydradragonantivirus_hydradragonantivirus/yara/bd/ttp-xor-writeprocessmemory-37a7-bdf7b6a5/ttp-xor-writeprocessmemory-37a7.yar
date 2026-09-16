rule TTP_XOR_WriteProcessMemory_37a7 {
  strings:
    $key_37a7 = { 60 d5 [2] 52 f7 [2] 54 c2 [2] 7a c2 [2] 45 de }

  condition:
    any of them
}