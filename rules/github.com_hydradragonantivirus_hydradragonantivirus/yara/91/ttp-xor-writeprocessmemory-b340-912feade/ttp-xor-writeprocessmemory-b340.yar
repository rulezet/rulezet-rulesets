rule TTP_XOR_WriteProcessMemory_b340 {
  strings:
    $key_b340 = { e4 32 [2] d6 10 [2] d0 25 [2] fe 25 [2] c1 39 }

  condition:
    any of them
}