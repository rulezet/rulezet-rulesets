rule TTP_XOR_WriteProcessMemory_3abe {
  strings:
    $key_3abe = { 6d cc [2] 5f ee [2] 59 db [2] 77 db [2] 48 c7 }

  condition:
    any of them
}