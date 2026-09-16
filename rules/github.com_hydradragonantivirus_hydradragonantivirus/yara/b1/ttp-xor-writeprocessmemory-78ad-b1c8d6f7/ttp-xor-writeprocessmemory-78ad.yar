rule TTP_XOR_WriteProcessMemory_78ad {
  strings:
    $key_78ad = { 2f df [2] 1d fd [2] 1b c8 [2] 35 c8 [2] 0a d4 }

  condition:
    any of them
}