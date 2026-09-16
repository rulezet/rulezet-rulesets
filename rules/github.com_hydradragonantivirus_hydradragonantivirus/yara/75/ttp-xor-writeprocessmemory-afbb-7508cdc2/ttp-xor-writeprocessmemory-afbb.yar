rule TTP_XOR_WriteProcessMemory_afbb {
  strings:
    $key_afbb = { f8 c9 [2] ca eb [2] cc de [2] e2 de [2] dd c2 }

  condition:
    any of them
}