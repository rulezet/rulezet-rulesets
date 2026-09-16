rule TTP_XOR_WriteProcessMemory_858e {
  strings:
    $key_858e = { d2 fc [2] e0 de [2] e6 eb [2] c8 eb [2] f7 f7 }

  condition:
    any of them
}