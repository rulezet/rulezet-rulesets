rule TTP_XOR_WriteProcessMemory_38ac {
  strings:
    $key_38ac = { 6f de [2] 5d fc [2] 5b c9 [2] 75 c9 [2] 4a d5 }

  condition:
    any of them
}