rule TTP_XOR_WriteProcessMemory_63dd {
  strings:
    $key_63dd = { 34 af [2] 06 8d [2] 00 b8 [2] 2e b8 [2] 11 a4 }

  condition:
    any of them
}