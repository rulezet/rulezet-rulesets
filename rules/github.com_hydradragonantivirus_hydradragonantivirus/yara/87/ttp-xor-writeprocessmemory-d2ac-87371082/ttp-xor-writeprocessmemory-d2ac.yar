rule TTP_XOR_WriteProcessMemory_d2ac {
  strings:
    $key_d2ac = { 85 de [2] b7 fc [2] b1 c9 [2] 9f c9 [2] a0 d5 }

  condition:
    any of them
}