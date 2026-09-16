rule TTP_XOR_WriteProcessMemory_b39c {
  strings:
    $key_b39c = { e4 ee [2] d6 cc [2] d0 f9 [2] fe f9 [2] c1 e5 }

  condition:
    any of them
}