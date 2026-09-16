rule TTP_XOR_WriteProcessMemory_f4be {
  strings:
    $key_f4be = { a3 cc [2] 91 ee [2] 97 db [2] b9 db [2] 86 c7 }

  condition:
    any of them
}