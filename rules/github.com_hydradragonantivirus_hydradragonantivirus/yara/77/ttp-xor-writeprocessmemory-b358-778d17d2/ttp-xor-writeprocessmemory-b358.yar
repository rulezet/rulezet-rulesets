rule TTP_XOR_WriteProcessMemory_b358 {
  strings:
    $key_b358 = { e4 2a [2] d6 08 [2] d0 3d [2] fe 3d [2] c1 21 }

  condition:
    any of them
}