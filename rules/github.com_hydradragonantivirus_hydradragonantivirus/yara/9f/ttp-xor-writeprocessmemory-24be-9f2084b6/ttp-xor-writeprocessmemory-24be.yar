rule TTP_XOR_WriteProcessMemory_24be {
  strings:
    $key_24be = { 73 cc [2] 41 ee [2] 47 db [2] 69 db [2] 56 c7 }

  condition:
    any of them
}