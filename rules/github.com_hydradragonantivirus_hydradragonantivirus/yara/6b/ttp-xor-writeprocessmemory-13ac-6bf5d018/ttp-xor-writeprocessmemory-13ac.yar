rule TTP_XOR_WriteProcessMemory_13ac {
  strings:
    $key_13ac = { 44 de [2] 76 fc [2] 70 c9 [2] 5e c9 [2] 61 d5 }

  condition:
    any of them
}