rule TTP_XOR_WriteProcessMemory_04ac {
  strings:
    $key_04ac = { 53 de [2] 61 fc [2] 67 c9 [2] 49 c9 [2] 76 d5 }

  condition:
    any of them
}