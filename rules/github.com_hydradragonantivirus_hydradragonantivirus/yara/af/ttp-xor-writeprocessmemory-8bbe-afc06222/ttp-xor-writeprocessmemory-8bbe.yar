rule TTP_XOR_WriteProcessMemory_8bbe {
  strings:
    $key_8bbe = { dc cc [2] ee ee [2] e8 db [2] c6 db [2] f9 c7 }

  condition:
    any of them
}