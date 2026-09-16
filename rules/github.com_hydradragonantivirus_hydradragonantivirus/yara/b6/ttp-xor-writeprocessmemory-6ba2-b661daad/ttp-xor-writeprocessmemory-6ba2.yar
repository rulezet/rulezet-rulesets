rule TTP_XOR_WriteProcessMemory_6ba2 {
  strings:
    $key_6ba2 = { 3c d0 [2] 0e f2 [2] 08 c7 [2] 26 c7 [2] 19 db }

  condition:
    any of them
}