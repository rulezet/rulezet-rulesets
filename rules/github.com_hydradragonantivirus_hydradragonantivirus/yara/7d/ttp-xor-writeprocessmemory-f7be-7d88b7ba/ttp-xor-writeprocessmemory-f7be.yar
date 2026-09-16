rule TTP_XOR_WriteProcessMemory_f7be {
  strings:
    $key_f7be = { a0 cc [2] 92 ee [2] 94 db [2] ba db [2] 85 c7 }

  condition:
    any of them
}