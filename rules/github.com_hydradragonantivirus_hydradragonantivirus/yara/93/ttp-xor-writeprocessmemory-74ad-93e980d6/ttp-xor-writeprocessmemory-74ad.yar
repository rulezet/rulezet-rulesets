rule TTP_XOR_WriteProcessMemory_74ad {
  strings:
    $key_74ad = { 23 df [2] 11 fd [2] 17 c8 [2] 39 c8 [2] 06 d4 }

  condition:
    any of them
}