rule TTP_XOR_WriteProcessMemory_f7ac {
  strings:
    $key_f7ac = { a0 de [2] 92 fc [2] 94 c9 [2] ba c9 [2] 85 d5 }

  condition:
    any of them
}