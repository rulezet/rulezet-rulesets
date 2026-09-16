rule TTP_XOR_WriteProcessMemory_38ad {
  strings:
    $key_38ad = { 6f df [2] 5d fd [2] 5b c8 [2] 75 c8 [2] 4a d4 }

  condition:
    any of them
}