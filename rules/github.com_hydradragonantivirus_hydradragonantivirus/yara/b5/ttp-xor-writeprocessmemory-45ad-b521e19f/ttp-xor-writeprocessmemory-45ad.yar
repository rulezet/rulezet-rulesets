rule TTP_XOR_WriteProcessMemory_45ad {
  strings:
    $key_45ad = { 12 df [2] 20 fd [2] 26 c8 [2] 08 c8 [2] 37 d4 }

  condition:
    any of them
}