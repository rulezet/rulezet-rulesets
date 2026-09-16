rule TTP_XOR_WriteProcessMemory_c5ac {
  strings:
    $key_c5ac = { 92 de [2] a0 fc [2] a6 c9 [2] 88 c9 [2] b7 d5 }

  condition:
    any of them
}