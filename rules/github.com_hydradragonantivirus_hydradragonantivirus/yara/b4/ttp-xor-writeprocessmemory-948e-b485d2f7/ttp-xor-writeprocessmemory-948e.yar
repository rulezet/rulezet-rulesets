rule TTP_XOR_WriteProcessMemory_948e {
  strings:
    $key_948e = { c3 fc [2] f1 de [2] f7 eb [2] d9 eb [2] e6 f7 }

  condition:
    any of them
}