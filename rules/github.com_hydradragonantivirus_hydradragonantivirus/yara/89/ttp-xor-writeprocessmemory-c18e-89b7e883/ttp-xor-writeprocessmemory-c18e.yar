rule TTP_XOR_WriteProcessMemory_c18e {
  strings:
    $key_c18e = { 96 fc [2] a4 de [2] a2 eb [2] 8c eb [2] b3 f7 }

  condition:
    any of them
}