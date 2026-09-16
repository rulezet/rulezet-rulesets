rule TTP_XOR_WriteProcessMemory_4ba2 {
  strings:
    $key_4ba2 = { 1c d0 [2] 2e f2 [2] 28 c7 [2] 06 c7 [2] 39 db }

  condition:
    any of them
}