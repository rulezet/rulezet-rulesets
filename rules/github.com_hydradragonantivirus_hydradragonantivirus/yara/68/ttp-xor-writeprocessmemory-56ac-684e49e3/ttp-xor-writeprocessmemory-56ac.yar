rule TTP_XOR_WriteProcessMemory_56ac {
  strings:
    $key_56ac = { 01 de [2] 33 fc [2] 35 c9 [2] 1b c9 [2] 24 d5 }

  condition:
    any of them
}