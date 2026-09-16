rule TTP_XOR_WriteProcessMemory_b18e {
  strings:
    $key_b18e = { e6 fc [2] d4 de [2] d2 eb [2] fc eb [2] c3 f7 }

  condition:
    any of them
}