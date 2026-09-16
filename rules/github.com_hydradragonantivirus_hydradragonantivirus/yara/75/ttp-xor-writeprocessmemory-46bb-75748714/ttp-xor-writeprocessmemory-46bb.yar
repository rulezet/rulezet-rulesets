rule TTP_XOR_WriteProcessMemory_46bb {
  strings:
    $key_46bb = { 11 c9 [2] 23 eb [2] 25 de [2] 0b de [2] 34 c2 }

  condition:
    any of them
}