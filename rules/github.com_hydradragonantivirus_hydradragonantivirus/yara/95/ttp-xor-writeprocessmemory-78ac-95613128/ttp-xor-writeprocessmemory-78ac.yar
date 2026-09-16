rule TTP_XOR_WriteProcessMemory_78ac {
  strings:
    $key_78ac = { 2f de [2] 1d fc [2] 1b c9 [2] 35 c9 [2] 0a d5 }

  condition:
    any of them
}