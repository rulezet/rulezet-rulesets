rule TTP_XOR_WriteProcessMemory_31ac {
  strings:
    $key_31ac = { 66 de [2] 54 fc [2] 52 c9 [2] 7c c9 [2] 43 d5 }

  condition:
    any of them
}