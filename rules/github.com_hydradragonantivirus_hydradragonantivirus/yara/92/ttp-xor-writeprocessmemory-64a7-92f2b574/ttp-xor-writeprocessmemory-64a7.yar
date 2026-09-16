rule TTP_XOR_WriteProcessMemory_64a7 {
  strings:
    $key_64a7 = { 33 d5 [2] 01 f7 [2] 07 c2 [2] 29 c2 [2] 16 de }

  condition:
    any of them
}