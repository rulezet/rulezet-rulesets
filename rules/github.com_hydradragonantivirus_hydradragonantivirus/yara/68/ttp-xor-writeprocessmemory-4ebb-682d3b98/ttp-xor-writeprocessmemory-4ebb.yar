rule TTP_XOR_WriteProcessMemory_4ebb {
  strings:
    $key_4ebb = { 19 c9 [2] 2b eb [2] 2d de [2] 03 de [2] 3c c2 }

  condition:
    any of them
}