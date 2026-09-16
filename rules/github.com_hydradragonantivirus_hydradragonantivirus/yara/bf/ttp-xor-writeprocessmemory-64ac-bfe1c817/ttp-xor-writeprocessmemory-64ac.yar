rule TTP_XOR_WriteProcessMemory_64ac {
  strings:
    $key_64ac = { 33 de [2] 01 fc [2] 07 c9 [2] 29 c9 [2] 16 d5 }

  condition:
    any of them
}