rule TTP_XOR_WriteProcessMemory_33ad {
  strings:
    $key_33ad = { 64 df [2] 56 fd [2] 50 c8 [2] 7e c8 [2] 41 d4 }

  condition:
    any of them
}