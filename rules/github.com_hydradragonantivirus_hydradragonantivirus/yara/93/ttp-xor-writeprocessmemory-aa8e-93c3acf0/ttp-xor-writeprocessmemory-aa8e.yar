rule TTP_XOR_WriteProcessMemory_aa8e {
  strings:
    $key_aa8e = { fd fc [2] cf de [2] c9 eb [2] e7 eb [2] d8 f7 }

  condition:
    any of them
}