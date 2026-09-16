rule TTP_XOR_WriteProcessMemory_afbe {
  strings:
    $key_afbe = { f8 cc [2] ca ee [2] cc db [2] e2 db [2] dd c7 }

  condition:
    any of them
}