rule TTP_XOR_WriteProcessMemory_34be {
  strings:
    $key_34be = { 63 cc [2] 51 ee [2] 57 db [2] 79 db [2] 46 c7 }

  condition:
    any of them
}