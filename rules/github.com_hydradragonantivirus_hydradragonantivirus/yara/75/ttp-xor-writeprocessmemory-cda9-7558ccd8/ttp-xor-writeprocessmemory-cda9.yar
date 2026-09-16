rule TTP_XOR_WriteProcessMemory_cda9 {
  strings:
    $key_cda9 = { 9a db [2] a8 f9 [2] ae cc [2] 80 cc [2] bf d0 }

  condition:
    any of them
}