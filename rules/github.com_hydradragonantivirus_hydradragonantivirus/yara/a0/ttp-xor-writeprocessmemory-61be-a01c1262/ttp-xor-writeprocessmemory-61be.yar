rule TTP_XOR_WriteProcessMemory_61be {
  strings:
    $key_61be = { 36 cc [2] 04 ee [2] 02 db [2] 2c db [2] 13 c7 }

  condition:
    any of them
}