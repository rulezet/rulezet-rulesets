rule TTP_XOR_WriteProcessMemory_77bb {
  strings:
    $key_77bb = { 20 c9 [2] 12 eb [2] 14 de [2] 3a de [2] 05 c2 }

  condition:
    any of them
}