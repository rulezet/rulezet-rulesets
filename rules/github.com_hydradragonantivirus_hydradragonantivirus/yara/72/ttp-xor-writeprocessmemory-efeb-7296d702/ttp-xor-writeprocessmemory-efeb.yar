rule TTP_XOR_WriteProcessMemory_efeb {
  strings:
    $key_efeb = { b8 99 [2] 8a bb [2] 8c 8e [2] a2 8e [2] 9d 92 }

  condition:
    any of them
}