rule TTP_XOR_WriteProcessMemory_818e {
  strings:
    $key_818e = { d6 fc [2] e4 de [2] e2 eb [2] cc eb [2] f3 f7 }

  condition:
    any of them
}