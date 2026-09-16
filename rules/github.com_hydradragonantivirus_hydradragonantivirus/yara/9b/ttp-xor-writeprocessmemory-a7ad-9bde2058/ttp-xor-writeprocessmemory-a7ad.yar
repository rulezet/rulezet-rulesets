rule TTP_XOR_WriteProcessMemory_a7ad {
  strings:
    $key_a7ad = { f0 df [2] c2 fd [2] c4 c8 [2] ea c8 [2] d5 d4 }

  condition:
    any of them
}