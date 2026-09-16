rule TTP_XOR_WriteProcessMemory_23ac {
  strings:
    $key_23ac = { 74 de [2] 46 fc [2] 40 c9 [2] 6e c9 [2] 51 d5 }

  condition:
    any of them
}