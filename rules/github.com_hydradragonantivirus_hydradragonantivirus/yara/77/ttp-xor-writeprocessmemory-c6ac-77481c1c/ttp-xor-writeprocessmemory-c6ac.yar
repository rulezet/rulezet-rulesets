rule TTP_XOR_WriteProcessMemory_c6ac {
  strings:
    $key_c6ac = { 91 de [2] a3 fc [2] a5 c9 [2] 8b c9 [2] b4 d5 }

  condition:
    any of them
}