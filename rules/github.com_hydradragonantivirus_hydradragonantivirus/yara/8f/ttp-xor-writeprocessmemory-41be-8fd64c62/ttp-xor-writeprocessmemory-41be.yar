rule TTP_XOR_WriteProcessMemory_41be {
  strings:
    $key_41be = { 16 cc [2] 24 ee [2] 22 db [2] 0c db [2] 33 c7 }

  condition:
    any of them
}