rule TTP_XOR_WriteProcessMemory_c4ac {
  strings:
    $key_c4ac = { 93 de [2] a1 fc [2] a7 c9 [2] 89 c9 [2] b6 d5 }

  condition:
    any of them
}