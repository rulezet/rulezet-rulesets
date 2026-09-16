rule TTP_XOR_WriteProcessMemory_26be {
  strings:
    $key_26be = { 71 cc [2] 43 ee [2] 45 db [2] 6b db [2] 54 c7 }

  condition:
    any of them
}