rule TTP_XOR_WriteProcessMemory_b38e {
  strings:
    $key_b38e = { e4 fc [2] d6 de [2] d0 eb [2] fe eb [2] c1 f7 }

  condition:
    any of them
}