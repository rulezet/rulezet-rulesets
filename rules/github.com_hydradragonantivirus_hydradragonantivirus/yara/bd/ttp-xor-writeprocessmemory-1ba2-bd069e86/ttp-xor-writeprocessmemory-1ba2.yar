rule TTP_XOR_WriteProcessMemory_1ba2 {
  strings:
    $key_1ba2 = { 4c d0 [2] 7e f2 [2] 78 c7 [2] 56 c7 [2] 69 db }

  condition:
    any of them
}