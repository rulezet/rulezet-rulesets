rule TTP_XOR_WriteProcessMemory_3ebb {
  strings:
    $key_3ebb = { 69 c9 [2] 5b eb [2] 5d de [2] 73 de [2] 4c c2 }

  condition:
    any of them
}