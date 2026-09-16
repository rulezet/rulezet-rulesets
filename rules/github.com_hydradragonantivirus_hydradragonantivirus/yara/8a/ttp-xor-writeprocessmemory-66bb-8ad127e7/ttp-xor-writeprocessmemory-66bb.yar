rule TTP_XOR_WriteProcessMemory_66bb {
  strings:
    $key_66bb = { 31 c9 [2] 03 eb [2] 05 de [2] 2b de [2] 14 c2 }

  condition:
    any of them
}