rule TTP_XOR_WriteProcessMemory_43bb {
  strings:
    $key_43bb = { 14 c9 [2] 26 eb [2] 20 de [2] 0e de [2] 31 c2 }

  condition:
    any of them
}