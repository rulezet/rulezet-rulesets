rule TTP_XOR_WriteProcessMemory_27ac {
  strings:
    $key_27ac = { 70 de [2] 42 fc [2] 44 c9 [2] 6a c9 [2] 55 d5 }

  condition:
    any of them
}