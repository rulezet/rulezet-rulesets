rule TTP_XOR_WriteProcessMemory_22ad {
  strings:
    $key_22ad = { 75 df [2] 47 fd [2] 41 c8 [2] 6f c8 [2] 50 d4 }

  condition:
    any of them
}