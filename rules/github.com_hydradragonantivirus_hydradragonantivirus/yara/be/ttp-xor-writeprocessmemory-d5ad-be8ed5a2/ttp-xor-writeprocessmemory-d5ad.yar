rule TTP_XOR_WriteProcessMemory_d5ad {
  strings:
    $key_d5ad = { 82 df [2] b0 fd [2] b6 c8 [2] 98 c8 [2] a7 d4 }

  condition:
    any of them
}