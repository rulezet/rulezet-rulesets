rule TTP_XOR_WriteProcessMemory_e9bb {
  strings:
    $key_e9bb = { be c9 [2] 8c eb [2] 8a de [2] a4 de [2] 9b c2 }

  condition:
    any of them
}