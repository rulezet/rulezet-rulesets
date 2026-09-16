rule TTP_XOR_WriteProcessMemory_15be {
  strings:
    $key_15be = { 42 cc [2] 70 ee [2] 76 db [2] 58 db [2] 67 c7 }

  condition:
    any of them
}