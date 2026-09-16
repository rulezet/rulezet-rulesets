rule TTP_XOR_WriteProcessMemory_507c {
  strings:
    $key_507c = { 07 0e [2] 35 2c [2] 33 19 [2] 1d 19 [2] 22 05 }

  condition:
    any of them
}