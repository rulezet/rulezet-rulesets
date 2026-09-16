rule TTP_XOR_WriteProcessMemory_1aa2 {
  strings:
    $key_1aa2 = { 4d d0 [2] 7f f2 [2] 79 c7 [2] 57 c7 [2] 68 db }

  condition:
    any of them
}