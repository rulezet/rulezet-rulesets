rule TTP_XOR_WriteProcessMemory_a9be {
  strings:
    $key_a9be = { fe cc [2] cc ee [2] ca db [2] e4 db [2] db c7 }

  condition:
    any of them
}