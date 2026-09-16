rule TTP_XOR_WriteProcessMemory_b48e {
  strings:
    $key_b48e = { e3 fc [2] d1 de [2] d7 eb [2] f9 eb [2] c6 f7 }

  condition:
    any of them
}