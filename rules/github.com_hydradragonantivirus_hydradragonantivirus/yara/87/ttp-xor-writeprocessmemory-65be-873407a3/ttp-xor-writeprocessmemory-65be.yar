rule TTP_XOR_WriteProcessMemory_65be {
  strings:
    $key_65be = { 32 cc [2] 00 ee [2] 06 db [2] 28 db [2] 17 c7 }

  condition:
    any of them
}