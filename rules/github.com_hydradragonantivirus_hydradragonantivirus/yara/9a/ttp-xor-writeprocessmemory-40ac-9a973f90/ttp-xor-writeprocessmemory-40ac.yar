rule TTP_XOR_WriteProcessMemory_40ac {
  strings:
    $key_40ac = { 17 de [2] 25 fc [2] 23 c9 [2] 0d c9 [2] 32 d5 }

  condition:
    any of them
}