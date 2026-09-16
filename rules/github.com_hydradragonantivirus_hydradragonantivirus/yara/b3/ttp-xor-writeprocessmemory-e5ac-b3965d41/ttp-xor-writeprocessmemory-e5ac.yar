rule TTP_XOR_WriteProcessMemory_e5ac {
  strings:
    $key_e5ac = { b2 de [2] 80 fc [2] 86 c9 [2] a8 c9 [2] 97 d5 }

  condition:
    any of them
}