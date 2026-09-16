rule TTP_XOR_WriteProcessMemory_f68e {
  strings:
    $key_f68e = { a1 fc [2] 93 de [2] 95 eb [2] bb eb [2] 84 f7 }

  condition:
    any of them
}