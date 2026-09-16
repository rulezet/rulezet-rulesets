rule TTP_XOR_WriteProcessMemory_8cbb {
  strings:
    $key_8cbb = { db c9 [2] e9 eb [2] ef de [2] c1 de [2] fe c2 }

  condition:
    any of them
}