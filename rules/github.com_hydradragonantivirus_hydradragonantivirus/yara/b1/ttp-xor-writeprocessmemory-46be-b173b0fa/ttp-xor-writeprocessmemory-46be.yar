rule TTP_XOR_WriteProcessMemory_46be {
  strings:
    $key_46be = { 11 cc [2] 23 ee [2] 25 db [2] 0b db [2] 34 c7 }

  condition:
    any of them
}