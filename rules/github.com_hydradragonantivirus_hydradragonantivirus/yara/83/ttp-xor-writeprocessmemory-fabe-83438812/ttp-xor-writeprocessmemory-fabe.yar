rule TTP_XOR_WriteProcessMemory_fabe {
  strings:
    $key_fabe = { ad cc [2] 9f ee [2] 99 db [2] b7 db [2] 88 c7 }

  condition:
    any of them
}