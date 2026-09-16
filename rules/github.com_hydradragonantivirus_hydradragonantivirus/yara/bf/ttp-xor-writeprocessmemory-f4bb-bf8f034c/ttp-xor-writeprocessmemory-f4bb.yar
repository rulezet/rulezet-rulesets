rule TTP_XOR_WriteProcessMemory_f4bb {
  strings:
    $key_f4bb = { a3 c9 [2] 91 eb [2] 97 de [2] b9 de [2] 86 c2 }

  condition:
    any of them
}