rule TTP_XOR_WriteProcessMemory_79ad {
  strings:
    $key_79ad = { 2e df [2] 1c fd [2] 1a c8 [2] 34 c8 [2] 0b d4 }

  condition:
    any of them
}