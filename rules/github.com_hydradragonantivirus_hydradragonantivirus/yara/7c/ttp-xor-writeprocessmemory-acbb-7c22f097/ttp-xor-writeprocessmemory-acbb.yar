rule TTP_XOR_WriteProcessMemory_acbb {
  strings:
    $key_acbb = { fb c9 [2] c9 eb [2] cf de [2] e1 de [2] de c2 }

  condition:
    any of them
}