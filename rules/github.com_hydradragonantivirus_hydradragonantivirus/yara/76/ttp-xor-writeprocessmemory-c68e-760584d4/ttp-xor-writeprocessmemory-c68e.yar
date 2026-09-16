rule TTP_XOR_WriteProcessMemory_c68e {
  strings:
    $key_c68e = { 91 fc [2] a3 de [2] a5 eb [2] 8b eb [2] b4 f7 }

  condition:
    any of them
}