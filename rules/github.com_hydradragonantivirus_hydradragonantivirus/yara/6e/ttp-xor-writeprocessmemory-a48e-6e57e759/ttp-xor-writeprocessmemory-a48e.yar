rule TTP_XOR_WriteProcessMemory_a48e {
  strings:
    $key_a48e = { f3 fc [2] c1 de [2] c7 eb [2] e9 eb [2] d6 f7 }

  condition:
    any of them
}