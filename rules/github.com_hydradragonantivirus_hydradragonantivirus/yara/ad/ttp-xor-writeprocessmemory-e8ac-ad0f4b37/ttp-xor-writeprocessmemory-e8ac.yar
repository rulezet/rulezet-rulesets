rule TTP_XOR_WriteProcessMemory_e8ac {
  strings:
    $key_e8ac = { bf de [2] 8d fc [2] 8b c9 [2] a5 c9 [2] 9a d5 }

  condition:
    any of them
}