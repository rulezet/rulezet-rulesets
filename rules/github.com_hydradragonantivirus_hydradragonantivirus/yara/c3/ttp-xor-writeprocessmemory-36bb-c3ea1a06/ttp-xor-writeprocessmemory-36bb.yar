rule TTP_XOR_WriteProcessMemory_36bb {
  strings:
    $key_36bb = { 61 c9 [2] 53 eb [2] 55 de [2] 7b de [2] 44 c2 }

  condition:
    any of them
}