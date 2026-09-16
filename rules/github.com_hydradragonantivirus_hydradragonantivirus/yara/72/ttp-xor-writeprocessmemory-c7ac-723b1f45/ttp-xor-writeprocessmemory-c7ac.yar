rule TTP_XOR_WriteProcessMemory_c7ac {
  strings:
    $key_c7ac = { 90 de [2] a2 fc [2] a4 c9 [2] 8a c9 [2] b5 d5 }

  condition:
    any of them
}