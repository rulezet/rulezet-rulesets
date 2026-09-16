rule TTP_XOR_WriteProcessMemory_00ad {
  strings:
    $key_00ad = { 57 df [2] 65 fd [2] 63 c8 [2] 4d c8 [2] 72 d4 }

  condition:
    any of them
}