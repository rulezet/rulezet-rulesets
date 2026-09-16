rule TTP_XOR_WriteProcessMemory_dabe {
  strings:
    $key_dabe = { 8d cc [2] bf ee [2] b9 db [2] 97 db [2] a8 c7 }

  condition:
    any of them
}