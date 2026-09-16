rule TTP_XOR_WriteProcessMemory_a558 {
  strings:
    $key_a558 = { f2 2a [2] c0 08 [2] c6 3d [2] e8 3d [2] d7 21 }

  condition:
    any of them
}