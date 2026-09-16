rule TTP_XOR_WriteProcessMemory_878e {
  strings:
    $key_878e = { d0 fc [2] e2 de [2] e4 eb [2] ca eb [2] f5 f7 }

  condition:
    any of them
}