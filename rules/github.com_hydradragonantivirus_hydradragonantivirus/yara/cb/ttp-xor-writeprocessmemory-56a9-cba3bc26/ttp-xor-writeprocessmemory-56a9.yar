rule TTP_XOR_WriteProcessMemory_56a9 {
  strings:
    $key_56a9 = { 01 db [2] 33 f9 [2] 35 cc [2] 1b cc [2] 24 d0 }

  condition:
    any of them
}