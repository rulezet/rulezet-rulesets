rule TTP_XOR_WriteProcessMemory_b350 {
  strings:
    $key_b350 = { e4 22 [2] d6 00 [2] d0 35 [2] fe 35 [2] c1 29 }

  condition:
    any of them
}