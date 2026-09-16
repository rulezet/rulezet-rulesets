rule TTP_XOR_WriteProcessMemory_61ac {
  strings:
    $key_61ac = { 36 de [2] 04 fc [2] 02 c9 [2] 2c c9 [2] 13 d5 }

  condition:
    any of them
}