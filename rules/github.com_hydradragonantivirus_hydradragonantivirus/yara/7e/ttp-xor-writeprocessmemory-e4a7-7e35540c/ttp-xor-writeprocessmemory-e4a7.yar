rule TTP_XOR_WriteProcessMemory_e4a7 {
  strings:
    $key_e4a7 = { b3 d5 [2] 81 f7 [2] 87 c2 [2] a9 c2 [2] 96 de }

  condition:
    any of them
}