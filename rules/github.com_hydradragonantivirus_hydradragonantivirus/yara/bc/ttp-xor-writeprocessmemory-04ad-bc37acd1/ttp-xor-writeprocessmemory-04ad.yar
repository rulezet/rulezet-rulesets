rule TTP_XOR_WriteProcessMemory_04ad {
  strings:
    $key_04ad = { 53 df [2] 61 fd [2] 67 c8 [2] 49 c8 [2] 76 d4 }

  condition:
    any of them
}