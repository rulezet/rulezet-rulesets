rule TTP_XOR_WriteProcessMemory_36be {
  strings:
    $key_36be = { 61 cc [2] 53 ee [2] 55 db [2] 7b db [2] 44 c7 }

  condition:
    any of them
}