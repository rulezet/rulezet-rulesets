rule TTP_XOR_WriteProcessMemory_b348 {
  strings:
    $key_b348 = { e4 3a [2] d6 18 [2] d0 2d [2] fe 2d [2] c1 31 }

  condition:
    any of them
}