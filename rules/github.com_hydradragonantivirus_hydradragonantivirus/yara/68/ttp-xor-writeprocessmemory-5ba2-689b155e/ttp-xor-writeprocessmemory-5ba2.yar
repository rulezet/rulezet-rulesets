rule TTP_XOR_WriteProcessMemory_5ba2 {
  strings:
    $key_5ba2 = { 0c d0 [2] 3e f2 [2] 38 c7 [2] 16 c7 [2] 29 db }

  condition:
    any of them
}