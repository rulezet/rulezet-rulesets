rule TTP_XOR_WriteProcessMemory_c08e {
  strings:
    $key_c08e = { 97 fc [2] a5 de [2] a3 eb [2] 8d eb [2] b2 f7 }

  condition:
    any of them
}