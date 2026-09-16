rule TTP_XOR_WriteProcessMemory_e5be {
  strings:
    $key_e5be = { b2 cc [2] 80 ee [2] 86 db [2] a8 db [2] 97 c7 }

  condition:
    any of them
}