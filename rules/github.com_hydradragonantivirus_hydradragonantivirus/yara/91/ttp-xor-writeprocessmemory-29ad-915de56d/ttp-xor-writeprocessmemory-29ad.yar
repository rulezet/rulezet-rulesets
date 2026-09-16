rule TTP_XOR_WriteProcessMemory_29ad {
  strings:
    $key_29ad = { 7e df [2] 4c fd [2] 4a c8 [2] 64 c8 [2] 5b d4 }

  condition:
    any of them
}