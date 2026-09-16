rule TTP_XOR_WriteProcessMemory_89ac {
  strings:
    $key_89ac = { de de [2] ec fc [2] ea c9 [2] c4 c9 [2] fb d5 }

  condition:
    any of them
}