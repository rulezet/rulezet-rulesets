rule TTP_XOR_WriteProcessMemory_d4ac {
  strings:
    $key_d4ac = { 83 de [2] b1 fc [2] b7 c9 [2] 99 c9 [2] a6 d5 }

  condition:
    any of them
}