rule TTP_XOR_WriteProcessMemory_45be {
  strings:
    $key_45be = { 12 cc [2] 20 ee [2] 26 db [2] 08 db [2] 37 c7 }

  condition:
    any of them
}