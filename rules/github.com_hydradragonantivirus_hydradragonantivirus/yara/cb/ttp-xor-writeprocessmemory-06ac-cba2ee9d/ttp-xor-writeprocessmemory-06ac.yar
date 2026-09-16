rule TTP_XOR_WriteProcessMemory_06ac {
  strings:
    $key_06ac = { 51 de [2] 63 fc [2] 65 c9 [2] 4b c9 [2] 74 d5 }

  condition:
    any of them
}