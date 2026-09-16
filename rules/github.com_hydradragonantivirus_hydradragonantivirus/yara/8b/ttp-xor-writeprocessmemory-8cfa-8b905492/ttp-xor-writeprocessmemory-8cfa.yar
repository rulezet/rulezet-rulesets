rule TTP_XOR_WriteProcessMemory_8cfa {
  strings:
    $key_8cfa = { db 88 [2] e9 aa [2] ef 9f [2] c1 9f [2] fe 83 }

  condition:
    any of them
}