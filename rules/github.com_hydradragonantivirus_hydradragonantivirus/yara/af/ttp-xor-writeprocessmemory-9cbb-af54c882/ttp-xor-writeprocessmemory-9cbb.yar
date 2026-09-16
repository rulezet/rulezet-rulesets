rule TTP_XOR_WriteProcessMemory_9cbb {
  strings:
    $key_9cbb = { cb c9 [2] f9 eb [2] ff de [2] d1 de [2] ee c2 }

  condition:
    any of them
}