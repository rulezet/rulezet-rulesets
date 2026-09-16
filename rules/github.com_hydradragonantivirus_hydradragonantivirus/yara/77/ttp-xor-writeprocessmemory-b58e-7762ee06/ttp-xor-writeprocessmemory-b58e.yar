rule TTP_XOR_WriteProcessMemory_b58e {
  strings:
    $key_b58e = { e2 fc [2] d0 de [2] d6 eb [2] f8 eb [2] c7 f7 }

  condition:
    any of them
}