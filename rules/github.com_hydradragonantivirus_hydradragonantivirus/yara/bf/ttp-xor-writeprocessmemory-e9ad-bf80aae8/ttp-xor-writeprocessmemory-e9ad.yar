rule TTP_XOR_WriteProcessMemory_e9ad {
  strings:
    $key_e9ad = { be df [2] 8c fd [2] 8a c8 [2] a4 c8 [2] 9b d4 }

  condition:
    any of them
}