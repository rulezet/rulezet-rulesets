rule TTP_XOR_WriteProcessMemory_b320 {
  strings:
    $key_b320 = { e4 52 [2] d6 70 [2] d0 45 [2] fe 45 [2] c1 59 }

  condition:
    any of them
}