rule TTP_XOR_WriteProcessMemory_b68e {
  strings:
    $key_b68e = { e1 fc [2] d3 de [2] d5 eb [2] fb eb [2] c4 f7 }

  condition:
    any of them
}