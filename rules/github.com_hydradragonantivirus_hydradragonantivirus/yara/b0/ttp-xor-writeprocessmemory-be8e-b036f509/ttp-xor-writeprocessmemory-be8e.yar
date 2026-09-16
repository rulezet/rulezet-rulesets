rule TTP_XOR_WriteProcessMemory_be8e {
  strings:
    $key_be8e = { e9 fc [2] db de [2] dd eb [2] f3 eb [2] cc f7 }

  condition:
    any of them
}