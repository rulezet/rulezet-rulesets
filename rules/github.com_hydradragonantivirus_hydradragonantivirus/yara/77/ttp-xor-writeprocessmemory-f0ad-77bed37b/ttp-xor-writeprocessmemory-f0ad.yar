rule TTP_XOR_WriteProcessMemory_f0ad {
  strings:
    $key_f0ad = { a7 df [2] 95 fd [2] 93 c8 [2] bd c8 [2] 82 d4 }

  condition:
    any of them
}