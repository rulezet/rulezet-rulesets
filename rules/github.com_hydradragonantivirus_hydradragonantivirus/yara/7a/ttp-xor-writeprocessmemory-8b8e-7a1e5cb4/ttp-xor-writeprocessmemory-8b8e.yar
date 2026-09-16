rule TTP_XOR_WriteProcessMemory_8b8e {
  strings:
    $key_8b8e = { dc fc [2] ee de [2] e8 eb [2] c6 eb [2] f9 f7 }

  condition:
    any of them
}