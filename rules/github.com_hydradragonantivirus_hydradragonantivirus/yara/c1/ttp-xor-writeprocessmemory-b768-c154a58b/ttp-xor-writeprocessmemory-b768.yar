rule TTP_XOR_WriteProcessMemory_b768 {
  strings:
    $key_b768 = { e0 1a [2] d2 38 [2] d4 0d [2] fa 0d [2] c5 11 }

  condition:
    any of them
}