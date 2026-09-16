rule TTP_XOR_WriteProcessMemory_30be {
  strings:
    $key_30be = { 67 cc [2] 55 ee [2] 53 db [2] 7d db [2] 42 c7 }

  condition:
    any of them
}