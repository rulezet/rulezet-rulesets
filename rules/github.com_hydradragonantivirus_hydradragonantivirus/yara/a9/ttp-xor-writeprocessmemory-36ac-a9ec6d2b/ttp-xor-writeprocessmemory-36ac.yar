rule TTP_XOR_WriteProcessMemory_36ac {
  strings:
    $key_36ac = { 61 de [2] 53 fc [2] 55 c9 [2] 7b c9 [2] 44 d5 }

  condition:
    any of them
}