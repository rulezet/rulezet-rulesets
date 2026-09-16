rule TTP_XOR_WriteProcessMemory_8dad {
  strings:
    $key_8dad = { da df [2] e8 fd [2] ee c8 [2] c0 c8 [2] ff d4 }

  condition:
    any of them
}