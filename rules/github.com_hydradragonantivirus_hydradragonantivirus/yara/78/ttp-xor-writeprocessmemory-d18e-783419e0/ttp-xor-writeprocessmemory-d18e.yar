rule TTP_XOR_WriteProcessMemory_d18e {
  strings:
    $key_d18e = { 86 fc [2] b4 de [2] b2 eb [2] 9c eb [2] a3 f7 }

  condition:
    any of them
}