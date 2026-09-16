rule TTP_XOR_WriteProcessMemory_a98e {
  strings:
    $key_a98e = { fe fc [2] cc de [2] ca eb [2] e4 eb [2] db f7 }

  condition:
    any of them
}