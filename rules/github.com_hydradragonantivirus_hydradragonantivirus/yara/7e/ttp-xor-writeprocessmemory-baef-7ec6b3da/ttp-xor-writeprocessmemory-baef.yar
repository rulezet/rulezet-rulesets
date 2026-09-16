rule TTP_XOR_WriteProcessMemory_baef {
  strings:
    $key_baef = { ed 9d [2] df bf [2] d9 8a [2] f7 8a [2] c8 96 }

  condition:
    any of them
}