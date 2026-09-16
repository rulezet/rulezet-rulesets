rule TTP_XOR_WriteProcessMemory_a2dd {
  strings:
    $key_a2dd = { f5 af [2] c7 8d [2] c1 b8 [2] ef b8 [2] d0 a4 }

  condition:
    any of them
}