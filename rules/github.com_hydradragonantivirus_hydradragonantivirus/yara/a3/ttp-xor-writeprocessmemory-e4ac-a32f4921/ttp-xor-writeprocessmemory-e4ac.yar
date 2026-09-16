rule TTP_XOR_WriteProcessMemory_e4ac {
  strings:
    $key_e4ac = { b3 de [2] 81 fc [2] 87 c9 [2] a9 c9 [2] 96 d5 }

  condition:
    any of them
}