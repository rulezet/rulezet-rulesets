rule TTP_XOR_WriteProcessMemory_44ac {
  strings:
    $key_44ac = { 13 de [2] 21 fc [2] 27 c9 [2] 09 c9 [2] 36 d5 }

  condition:
    any of them
}