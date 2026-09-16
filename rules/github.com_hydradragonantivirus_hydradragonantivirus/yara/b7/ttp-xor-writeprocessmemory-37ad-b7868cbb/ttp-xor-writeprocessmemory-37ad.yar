rule TTP_XOR_WriteProcessMemory_37ad {
  strings:
    $key_37ad = { 60 df [2] 52 fd [2] 54 c8 [2] 7a c8 [2] 45 d4 }

  condition:
    any of them
}