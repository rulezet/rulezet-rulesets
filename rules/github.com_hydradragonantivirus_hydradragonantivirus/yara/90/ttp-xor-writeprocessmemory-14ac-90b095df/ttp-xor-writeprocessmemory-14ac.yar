rule TTP_XOR_WriteProcessMemory_14ac {
  strings:
    $key_14ac = { 43 de [2] 71 fc [2] 77 c9 [2] 59 c9 [2] 66 d5 }

  condition:
    any of them
}