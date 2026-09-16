rule TTP_XOR_WriteProcessMemory_8cee {
  strings:
    $key_8cee = { db 9c [2] e9 be [2] ef 8b [2] c1 8b [2] fe 97 }

  condition:
    any of them
}