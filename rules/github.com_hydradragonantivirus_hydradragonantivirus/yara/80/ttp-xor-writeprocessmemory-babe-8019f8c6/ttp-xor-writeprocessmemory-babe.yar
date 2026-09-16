rule TTP_XOR_WriteProcessMemory_babe {
  strings:
    $key_babe = { ed cc [2] df ee [2] d9 db [2] f7 db [2] c8 c7 }

  condition:
    any of them
}