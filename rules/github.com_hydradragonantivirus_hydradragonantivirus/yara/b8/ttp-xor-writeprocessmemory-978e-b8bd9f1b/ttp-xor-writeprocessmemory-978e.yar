rule TTP_XOR_WriteProcessMemory_978e {
  strings:
    $key_978e = { c0 fc [2] f2 de [2] f4 eb [2] da eb [2] e5 f7 }

  condition:
    any of them
}