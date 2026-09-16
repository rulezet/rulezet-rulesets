rule TTP_XOR_WriteProcessMemory_baec {
  strings:
    $key_baec = { ed 9e [2] df bc [2] d9 89 [2] f7 89 [2] c8 95 }

  condition:
    any of them
}