rule TTP_XOR_WriteProcessMemory_77dd {
  strings:
    $key_77dd = { 20 af [2] 12 8d [2] 14 b8 [2] 3a b8 [2] 05 a4 }

  condition:
    any of them
}