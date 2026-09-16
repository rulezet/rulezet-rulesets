rule TTP_XOR_WriteProcessMemory_18ac {
  strings:
    $key_18ac = { 4f de [2] 7d fc [2] 7b c9 [2] 55 c9 [2] 6a d5 }

  condition:
    any of them
}