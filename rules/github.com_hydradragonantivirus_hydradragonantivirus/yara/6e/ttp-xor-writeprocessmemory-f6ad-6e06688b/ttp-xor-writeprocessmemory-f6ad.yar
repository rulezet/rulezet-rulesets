rule TTP_XOR_WriteProcessMemory_f6ad {
  strings:
    $key_f6ad = { a1 df [2] 93 fd [2] 95 c8 [2] bb c8 [2] 84 d4 }

  condition:
    any of them
}