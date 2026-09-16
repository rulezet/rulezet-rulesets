rule TTP_XOR_WriteProcessMemory_09bb {
  strings:
    $key_09bb = { 5e c9 [2] 6c eb [2] 6a de [2] 44 de [2] 7b c2 }

  condition:
    any of them
}