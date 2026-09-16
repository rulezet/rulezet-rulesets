rule TTP_XOR_WriteProcessMemory_838e {
  strings:
    $key_838e = { d4 fc [2] e6 de [2] e0 eb [2] ce eb [2] f1 f7 }

  condition:
    any of them
}