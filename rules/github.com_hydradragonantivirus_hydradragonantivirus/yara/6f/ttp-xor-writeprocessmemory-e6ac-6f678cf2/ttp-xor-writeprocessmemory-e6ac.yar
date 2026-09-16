rule TTP_XOR_WriteProcessMemory_e6ac {
  strings:
    $key_e6ac = { b1 de [2] 83 fc [2] 85 c9 [2] ab c9 [2] 94 d5 }

  condition:
    any of them
}