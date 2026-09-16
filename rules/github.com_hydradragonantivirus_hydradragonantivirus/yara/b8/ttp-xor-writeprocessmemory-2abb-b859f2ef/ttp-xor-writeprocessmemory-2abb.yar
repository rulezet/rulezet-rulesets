rule TTP_XOR_WriteProcessMemory_2abb {
  strings:
    $key_2abb = { 7d c9 [2] 4f eb [2] 49 de [2] 67 de [2] 58 c2 }

  condition:
    any of them
}