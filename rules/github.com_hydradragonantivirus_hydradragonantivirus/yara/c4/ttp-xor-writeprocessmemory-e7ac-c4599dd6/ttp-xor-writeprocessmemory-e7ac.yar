rule TTP_XOR_WriteProcessMemory_e7ac {
  strings:
    $key_e7ac = { b0 de [2] 82 fc [2] 84 c9 [2] aa c9 [2] 95 d5 }

  condition:
    any of them
}