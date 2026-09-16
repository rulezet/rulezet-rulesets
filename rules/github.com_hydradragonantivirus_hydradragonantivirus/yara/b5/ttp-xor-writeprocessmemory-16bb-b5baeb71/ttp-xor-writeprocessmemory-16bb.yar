rule TTP_XOR_WriteProcessMemory_16bb {
  strings:
    $key_16bb = { 41 c9 [2] 73 eb [2] 75 de [2] 5b de [2] 64 c2 }

  condition:
    any of them
}