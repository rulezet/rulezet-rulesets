rule TTP_XOR_WriteProcessMemory_54ac {
  strings:
    $key_54ac = { 03 de [2] 31 fc [2] 37 c9 [2] 19 c9 [2] 26 d5 }

  condition:
    any of them
}