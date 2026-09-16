rule TTP_XOR_WriteProcessMemory_07ac {
  strings:
    $key_07ac = { 50 de [2] 62 fc [2] 64 c9 [2] 4a c9 [2] 75 d5 }

  condition:
    any of them
}