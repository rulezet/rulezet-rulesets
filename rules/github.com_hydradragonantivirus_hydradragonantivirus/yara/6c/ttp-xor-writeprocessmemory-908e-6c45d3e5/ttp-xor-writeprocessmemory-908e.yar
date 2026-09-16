rule TTP_XOR_WriteProcessMemory_908e {
  strings:
    $key_908e = { c7 fc [2] f5 de [2] f3 eb [2] dd eb [2] e2 f7 }

  condition:
    any of them
}