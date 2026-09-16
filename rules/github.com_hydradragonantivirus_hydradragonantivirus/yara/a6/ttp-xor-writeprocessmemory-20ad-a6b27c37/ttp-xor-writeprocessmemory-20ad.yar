rule TTP_XOR_WriteProcessMemory_20ad {
  strings:
    $key_20ad = { 77 df [2] 45 fd [2] 43 c8 [2] 6d c8 [2] 52 d4 }

  condition:
    any of them
}