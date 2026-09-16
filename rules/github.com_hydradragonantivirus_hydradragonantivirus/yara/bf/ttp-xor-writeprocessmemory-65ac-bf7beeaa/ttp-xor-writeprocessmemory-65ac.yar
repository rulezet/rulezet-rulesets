rule TTP_XOR_WriteProcessMemory_65ac {
  strings:
    $key_65ac = { 32 de [2] 00 fc [2] 06 c9 [2] 28 c9 [2] 17 d5 }

  condition:
    any of them
}