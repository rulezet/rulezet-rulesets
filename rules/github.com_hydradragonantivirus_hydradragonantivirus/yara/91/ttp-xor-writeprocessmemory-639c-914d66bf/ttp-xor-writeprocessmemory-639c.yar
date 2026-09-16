rule TTP_XOR_WriteProcessMemory_639c {
  strings:
    $key_639c = { 34 ee [2] 06 cc [2] 00 f9 [2] 2e f9 [2] 11 e5 }

  condition:
    any of them
}