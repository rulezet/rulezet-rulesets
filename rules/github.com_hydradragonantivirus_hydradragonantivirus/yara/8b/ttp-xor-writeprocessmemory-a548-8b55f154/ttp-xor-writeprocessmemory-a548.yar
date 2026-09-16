rule TTP_XOR_WriteProcessMemory_a548 {
  strings:
    $key_a548 = { f2 3a [2] c0 18 [2] c6 2d [2] e8 2d [2] d7 31 }

  condition:
    any of them
}