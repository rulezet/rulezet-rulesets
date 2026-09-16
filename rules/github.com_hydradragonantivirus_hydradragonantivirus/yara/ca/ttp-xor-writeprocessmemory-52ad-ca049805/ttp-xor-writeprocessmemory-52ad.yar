rule TTP_XOR_WriteProcessMemory_52ad {
  strings:
    $key_52ad = { 05 df [2] 37 fd [2] 31 c8 [2] 1f c8 [2] 20 d4 }

  condition:
    any of them
}