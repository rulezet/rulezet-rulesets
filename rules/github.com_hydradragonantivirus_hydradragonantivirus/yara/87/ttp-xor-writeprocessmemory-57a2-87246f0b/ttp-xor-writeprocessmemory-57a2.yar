rule TTP_XOR_WriteProcessMemory_57a2 {
  strings:
    $key_57a2 = { 00 d0 [2] 32 f2 [2] 34 c7 [2] 1a c7 [2] 25 db }

  condition:
    any of them
}