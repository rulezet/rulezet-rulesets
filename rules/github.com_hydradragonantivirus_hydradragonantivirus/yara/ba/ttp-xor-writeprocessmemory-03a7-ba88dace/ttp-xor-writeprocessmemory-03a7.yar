rule TTP_XOR_WriteProcessMemory_03a7 {
  strings:
    $key_03a7 = { 54 d5 [2] 66 f7 [2] 60 c2 [2] 4e c2 [2] 71 de }

  condition:
    any of them
}