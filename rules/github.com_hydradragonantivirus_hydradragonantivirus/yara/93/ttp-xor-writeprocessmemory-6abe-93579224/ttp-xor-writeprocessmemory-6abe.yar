rule TTP_XOR_WriteProcessMemory_6abe {
  strings:
    $key_6abe = { 3d cc [2] 0f ee [2] 09 db [2] 27 db [2] 18 c7 }

  condition:
    any of them
}