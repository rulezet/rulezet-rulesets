rule TTP_XOR_WriteProcessMemory_54ad {
  strings:
    $key_54ad = { 03 df [2] 31 fd [2] 37 c8 [2] 19 c8 [2] 26 d4 }

  condition:
    any of them
}