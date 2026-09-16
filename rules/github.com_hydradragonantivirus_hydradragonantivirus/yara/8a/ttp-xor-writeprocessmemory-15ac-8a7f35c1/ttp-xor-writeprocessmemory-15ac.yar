rule TTP_XOR_WriteProcessMemory_15ac {
  strings:
    $key_15ac = { 42 de [2] 70 fc [2] 76 c9 [2] 58 c9 [2] 67 d5 }

  condition:
    any of them
}