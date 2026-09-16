rule TTP_XOR_WriteProcessMemory_b3c1 {
  strings:
    $key_b3c1 = { e4 b3 [2] d6 91 [2] d0 a4 [2] fe a4 [2] c1 b8 }

  condition:
    any of them
}