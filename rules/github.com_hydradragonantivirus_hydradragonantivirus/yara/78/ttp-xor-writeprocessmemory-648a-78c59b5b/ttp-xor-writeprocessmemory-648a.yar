rule TTP_XOR_WriteProcessMemory_648a {
  strings:
    $key_648a = { 33 f8 [2] 01 da [2] 07 ef [2] 29 ef [2] 16 f3 }

  condition:
    any of them
}