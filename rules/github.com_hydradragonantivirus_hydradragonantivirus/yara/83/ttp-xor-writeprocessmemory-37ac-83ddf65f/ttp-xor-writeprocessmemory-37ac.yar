rule TTP_XOR_WriteProcessMemory_37ac {
  strings:
    $key_37ac = { 60 de [2] 52 fc [2] 54 c9 [2] 7a c9 [2] 45 d5 }

  condition:
    any of them
}