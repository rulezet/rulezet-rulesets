rule TTP_XOR_WriteProcessMemory_9abe {
  strings:
    $key_9abe = { cd cc [2] ff ee [2] f9 db [2] d7 db [2] e8 c7 }

  condition:
    any of them
}