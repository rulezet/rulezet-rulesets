rule TTP_XOR_WriteProcessMemory_49ad {
  strings:
    $key_49ad = { 1e df [2] 2c fd [2] 2a c8 [2] 04 c8 [2] 3b d4 }

  condition:
    any of them
}