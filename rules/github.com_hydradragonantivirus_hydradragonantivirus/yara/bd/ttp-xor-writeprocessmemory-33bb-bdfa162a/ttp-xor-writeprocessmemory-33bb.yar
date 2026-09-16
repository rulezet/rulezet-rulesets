rule TTP_XOR_WriteProcessMemory_33bb {
  strings:
    $key_33bb = { 64 c9 [2] 56 eb [2] 50 de [2] 7e de [2] 41 c2 }

  condition:
    any of them
}