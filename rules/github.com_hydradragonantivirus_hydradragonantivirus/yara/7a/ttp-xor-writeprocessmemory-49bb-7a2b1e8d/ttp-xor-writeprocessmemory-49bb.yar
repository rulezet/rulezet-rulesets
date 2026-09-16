rule TTP_XOR_WriteProcessMemory_49bb {
  strings:
    $key_49bb = { 1e c9 [2] 2c eb [2] 2a de [2] 04 de [2] 3b c2 }

  condition:
    any of them
}