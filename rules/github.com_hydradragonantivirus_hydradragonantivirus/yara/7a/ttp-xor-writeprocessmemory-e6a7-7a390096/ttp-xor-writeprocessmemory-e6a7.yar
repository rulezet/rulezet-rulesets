rule TTP_XOR_WriteProcessMemory_e6a7 {
  strings:
    $key_e6a7 = { b1 d5 [2] 83 f7 [2] 85 c2 [2] ab c2 [2] 94 de }

  condition:
    any of them
}