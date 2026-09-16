rule TTP_XOR_WriteProcessMemory_e0a7 {
  strings:
    $key_e0a7 = { b7 d5 [2] 85 f7 [2] 83 c2 [2] ad c2 [2] 92 de }

  condition:
    any of them
}