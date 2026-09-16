rule TTP_XOR_WriteProcessMemory_f6a9 {
  strings:
    $key_f6a9 = { a1 db [2] 93 f9 [2] 95 cc [2] bb cc [2] 84 d0 }

  condition:
    any of them
}