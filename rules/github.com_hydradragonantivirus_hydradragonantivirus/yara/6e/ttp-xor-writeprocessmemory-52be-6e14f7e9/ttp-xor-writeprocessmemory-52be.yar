rule TTP_XOR_WriteProcessMemory_52be {
  strings:
    $key_52be = { 05 cc [2] 37 ee [2] 31 db [2] 1f db [2] 20 c7 }

  condition:
    any of them
}