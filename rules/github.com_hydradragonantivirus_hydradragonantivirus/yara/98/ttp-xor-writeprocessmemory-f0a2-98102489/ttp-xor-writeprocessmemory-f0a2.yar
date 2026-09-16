rule TTP_XOR_WriteProcessMemory_f0a2 {
  strings:
    $key_f0a2 = { a7 d0 [2] 95 f2 [2] 93 c7 [2] bd c7 [2] 82 db }

  condition:
    any of them
}