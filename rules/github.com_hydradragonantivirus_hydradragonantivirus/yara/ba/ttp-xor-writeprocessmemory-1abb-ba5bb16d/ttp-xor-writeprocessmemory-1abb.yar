rule TTP_XOR_WriteProcessMemory_1abb {
  strings:
    $key_1abb = { 4d c9 [2] 7f eb [2] 79 de [2] 57 de [2] 68 c2 }

  condition:
    any of them
}