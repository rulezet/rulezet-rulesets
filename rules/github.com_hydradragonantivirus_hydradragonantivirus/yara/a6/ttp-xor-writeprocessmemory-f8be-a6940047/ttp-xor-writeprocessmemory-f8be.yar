rule TTP_XOR_WriteProcessMemory_f8be {
  strings:
    $key_f8be = { af cc [2] 9d ee [2] 9b db [2] b5 db [2] 8a c7 }

  condition:
    any of them
}