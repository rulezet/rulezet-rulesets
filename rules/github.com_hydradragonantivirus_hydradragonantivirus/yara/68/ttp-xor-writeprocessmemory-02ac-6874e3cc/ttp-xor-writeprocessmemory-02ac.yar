rule TTP_XOR_WriteProcessMemory_02ac {
  strings:
    $key_02ac = { 55 de [2] 67 fc [2] 61 c9 [2] 4f c9 [2] 70 d5 }

  condition:
    any of them
}