rule TTP_XOR_WriteProcessMemory_af8e {
  strings:
    $key_af8e = { f8 fc [2] ca de [2] cc eb [2] e2 eb [2] dd f7 }

  condition:
    any of them
}