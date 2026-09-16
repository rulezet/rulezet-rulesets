rule TTP_XOR_WriteProcessMemory_a4ad {
  strings:
    $key_a4ad = { f3 df [2] c1 fd [2] c7 c8 [2] e9 c8 [2] d6 d4 }

  condition:
    any of them
}