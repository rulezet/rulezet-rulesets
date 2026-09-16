rule TTP_XOR_WriteProcessMemory_69bb {
  strings:
    $key_69bb = { 3e c9 [2] 0c eb [2] 0a de [2] 24 de [2] 1b c2 }

  condition:
    any of them
}