rule TTP_XOR_WriteProcessMemory_c8ad {
  strings:
    $key_c8ad = { 9f df [2] ad fd [2] ab c8 [2] 85 c8 [2] ba d4 }

  condition:
    any of them
}