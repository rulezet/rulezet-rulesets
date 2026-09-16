rule TTP_XOR_WriteProcessMemory_c2ac {
  strings:
    $key_c2ac = { 95 de [2] a7 fc [2] a1 c9 [2] 8f c9 [2] b0 d5 }

  condition:
    any of them
}