rule TTP_XOR_WriteProcessMemory_3abb {
  strings:
    $key_3abb = { 6d c9 [2] 5f eb [2] 59 de [2] 77 de [2] 48 c2 }

  condition:
    any of them
}