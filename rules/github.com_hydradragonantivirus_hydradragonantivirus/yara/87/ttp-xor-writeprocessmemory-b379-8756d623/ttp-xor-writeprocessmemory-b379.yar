rule TTP_XOR_WriteProcessMemory_b379 {
  strings:
    $key_b379 = { e4 0b [2] d6 29 [2] d0 1c [2] fe 1c [2] c1 00 }

  condition:
    any of them
}