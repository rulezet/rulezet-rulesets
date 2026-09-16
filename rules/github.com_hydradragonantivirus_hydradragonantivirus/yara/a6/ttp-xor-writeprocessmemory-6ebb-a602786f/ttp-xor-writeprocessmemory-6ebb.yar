rule TTP_XOR_WriteProcessMemory_6ebb {
  strings:
    $key_6ebb = { 39 c9 [2] 0b eb [2] 0d de [2] 23 de [2] 1c c2 }

  condition:
    any of them
}