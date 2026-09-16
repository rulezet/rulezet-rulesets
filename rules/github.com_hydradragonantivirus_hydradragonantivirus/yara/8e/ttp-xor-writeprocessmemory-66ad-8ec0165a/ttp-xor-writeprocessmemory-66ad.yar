rule TTP_XOR_WriteProcessMemory_66ad {
  strings:
    $key_66ad = { 31 df [2] 03 fd [2] 05 c8 [2] 2b c8 [2] 14 d4 }

  condition:
    any of them
}