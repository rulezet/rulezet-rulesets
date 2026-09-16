rule TTP_XOR_WriteProcessMemory_d8be {
  strings:
    $key_d8be = { 8f cc [2] bd ee [2] bb db [2] 95 db [2] aa c7 }

  condition:
    any of them
}