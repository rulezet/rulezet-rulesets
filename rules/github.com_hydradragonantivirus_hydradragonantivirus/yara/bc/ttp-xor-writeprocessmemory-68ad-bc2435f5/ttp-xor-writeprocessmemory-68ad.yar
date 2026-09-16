rule TTP_XOR_WriteProcessMemory_68ad {
  strings:
    $key_68ad = { 3f df [2] 0d fd [2] 0b c8 [2] 25 c8 [2] 1a d4 }

  condition:
    any of them
}