rule TTP_XOR_WriteProcessMemory_37bb {
  strings:
    $key_37bb = { 60 c9 [2] 52 eb [2] 54 de [2] 7a de [2] 45 c2 }

  condition:
    any of them
}