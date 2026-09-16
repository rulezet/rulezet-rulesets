rule TTP_XOR_WriteProcessMemory_42ad {
  strings:
    $key_42ad = { 15 df [2] 27 fd [2] 21 c8 [2] 0f c8 [2] 30 d4 }

  condition:
    any of them
}