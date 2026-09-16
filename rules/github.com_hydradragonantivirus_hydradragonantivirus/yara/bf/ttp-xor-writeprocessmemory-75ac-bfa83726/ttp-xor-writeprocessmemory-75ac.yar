rule TTP_XOR_WriteProcessMemory_75ac {
  strings:
    $key_75ac = { 22 de [2] 10 fc [2] 16 c9 [2] 38 c9 [2] 07 d5 }

  condition:
    any of them
}