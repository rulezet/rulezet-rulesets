rule TTP_XOR_WriteProcessMemory_b28e {
  strings:
    $key_b28e = { e5 fc [2] d7 de [2] d1 eb [2] ff eb [2] c0 f7 }

  condition:
    any of them
}