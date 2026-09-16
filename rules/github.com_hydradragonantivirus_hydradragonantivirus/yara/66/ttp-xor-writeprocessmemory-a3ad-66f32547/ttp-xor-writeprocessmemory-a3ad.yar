rule TTP_XOR_WriteProcessMemory_a3ad {
  strings:
    $key_a3ad = { f4 df [2] c6 fd [2] c0 c8 [2] ee c8 [2] d1 d4 }

  condition:
    any of them
}