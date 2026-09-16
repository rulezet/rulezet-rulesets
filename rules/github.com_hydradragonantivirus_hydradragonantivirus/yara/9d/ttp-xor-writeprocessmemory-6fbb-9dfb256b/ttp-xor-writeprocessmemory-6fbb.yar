rule TTP_XOR_WriteProcessMemory_6fbb {
  strings:
    $key_6fbb = { 38 c9 [2] 0a eb [2] 0c de [2] 22 de [2] 1d c2 }

  condition:
    any of them
}