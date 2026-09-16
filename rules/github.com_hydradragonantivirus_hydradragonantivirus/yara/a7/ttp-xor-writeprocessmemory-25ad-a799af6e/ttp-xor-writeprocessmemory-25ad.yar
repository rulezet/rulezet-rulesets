rule TTP_XOR_WriteProcessMemory_25ad {
  strings:
    $key_25ad = { 72 df [2] 40 fd [2] 46 c8 [2] 68 c8 [2] 57 d4 }

  condition:
    any of them
}