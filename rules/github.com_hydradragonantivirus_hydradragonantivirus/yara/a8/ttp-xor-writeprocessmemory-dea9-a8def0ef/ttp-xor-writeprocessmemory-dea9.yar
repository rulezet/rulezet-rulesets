rule TTP_XOR_WriteProcessMemory_dea9 {
  strings:
    $key_dea9 = { 89 db [2] bb f9 [2] bd cc [2] 93 cc [2] ac d0 }

  condition:
    any of them
}