rule TTP_XOR_WriteProcessMemory_9cad {
  strings:
    $key_9cad = { cb df [2] f9 fd [2] ff c8 [2] d1 c8 [2] ee d4 }

  condition:
    any of them
}