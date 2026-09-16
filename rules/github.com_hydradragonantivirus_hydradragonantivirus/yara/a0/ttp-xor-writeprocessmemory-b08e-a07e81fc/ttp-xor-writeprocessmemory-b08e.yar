rule TTP_XOR_WriteProcessMemory_b08e {
  strings:
    $key_b08e = { e7 fc [2] d5 de [2] d3 eb [2] fd eb [2] c2 f7 }

  condition:
    any of them
}