rule TTP_XOR_WriteProcessMemory_a9bb {
  strings:
    $key_a9bb = { fe c9 [2] cc eb [2] ca de [2] e4 de [2] db c2 }

  condition:
    any of them
}