rule TTP_XOR_WriteProcessMemory_79bb {
  strings:
    $key_79bb = { 2e c9 [2] 1c eb [2] 1a de [2] 34 de [2] 0b c2 }

  condition:
    any of them
}