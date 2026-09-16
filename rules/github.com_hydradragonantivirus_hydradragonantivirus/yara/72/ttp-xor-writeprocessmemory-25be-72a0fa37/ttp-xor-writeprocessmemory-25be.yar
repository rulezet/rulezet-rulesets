rule TTP_XOR_WriteProcessMemory_25be {
  strings:
    $key_25be = { 72 cc [2] 40 ee [2] 46 db [2] 68 db [2] 57 c7 }

  condition:
    any of them
}