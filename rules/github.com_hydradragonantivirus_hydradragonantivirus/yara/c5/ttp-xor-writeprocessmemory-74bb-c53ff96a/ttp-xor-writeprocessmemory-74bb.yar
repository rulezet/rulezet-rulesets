rule TTP_XOR_WriteProcessMemory_74bb {
  strings:
    $key_74bb = { 23 c9 [2] 11 eb [2] 17 de [2] 39 de [2] 06 c2 }

  condition:
    any of them
}