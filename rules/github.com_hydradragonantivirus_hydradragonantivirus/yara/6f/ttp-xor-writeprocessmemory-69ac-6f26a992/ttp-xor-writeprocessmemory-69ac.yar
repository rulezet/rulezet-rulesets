rule TTP_XOR_WriteProcessMemory_69ac {
  strings:
    $key_69ac = { 3e de [2] 0c fc [2] 0a c9 [2] 24 c9 [2] 1b d5 }

  condition:
    any of them
}