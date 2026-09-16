rule TTP_XOR_WriteProcessMemory_8e80 {
  strings:
    $key_8e80 = { d9 f2 [2] eb d0 [2] ed e5 [2] c3 e5 [2] fc f9 }

  condition:
    any of them
}