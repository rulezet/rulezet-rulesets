rule TTP_XOR_WriteProcessMemory_3fbb {
  strings:
    $key_3fbb = { 68 c9 [2] 5a eb [2] 5c de [2] 72 de [2] 4d c2 }

  condition:
    any of them
}