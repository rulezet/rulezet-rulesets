rule TTP_XOR_WriteProcessMemory_4aa2 {
  strings:
    $key_4aa2 = { 1d d0 [2] 2f f2 [2] 29 c7 [2] 07 c7 [2] 38 db }

  condition:
    any of them
}