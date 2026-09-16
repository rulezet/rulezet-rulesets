rule TTP_XOR_WriteProcessMemory_22be {
  strings:
    $key_22be = { 75 cc [2] 47 ee [2] 41 db [2] 6f db [2] 50 c7 }

  condition:
    any of them
}