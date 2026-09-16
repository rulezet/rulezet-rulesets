rule TTP_XOR_WriteProcessMemory_26ad {
  strings:
    $key_26ad = { 71 df [2] 43 fd [2] 45 c8 [2] 6b c8 [2] 54 d4 }

  condition:
    any of them
}