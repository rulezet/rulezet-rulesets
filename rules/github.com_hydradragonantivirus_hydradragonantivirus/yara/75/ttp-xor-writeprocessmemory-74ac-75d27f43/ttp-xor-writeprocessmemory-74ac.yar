rule TTP_XOR_WriteProcessMemory_74ac {
  strings:
    $key_74ac = { 23 de [2] 11 fc [2] 17 c9 [2] 39 c9 [2] 06 d5 }

  condition:
    any of them
}