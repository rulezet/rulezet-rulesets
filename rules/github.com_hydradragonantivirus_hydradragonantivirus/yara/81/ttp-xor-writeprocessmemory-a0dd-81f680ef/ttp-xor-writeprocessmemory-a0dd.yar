rule TTP_XOR_WriteProcessMemory_a0dd {
  strings:
    $key_a0dd = { f7 af [2] c5 8d [2] c3 b8 [2] ed b8 [2] d2 a4 }

  condition:
    any of them
}