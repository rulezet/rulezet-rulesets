rule TTP_XOR_WriteProcessMemory_feeb {
  strings:
    $key_feeb = { a9 99 [2] 9b bb [2] 9d 8e [2] b3 8e [2] 8c 92 }

  condition:
    any of them
}