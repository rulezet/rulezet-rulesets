rule TTP_XOR_WriteProcessMemory_a5ad {
  strings:
    $key_a5ad = { f2 df [2] c0 fd [2] c6 c8 [2] e8 c8 [2] d7 d4 }

  condition:
    any of them
}