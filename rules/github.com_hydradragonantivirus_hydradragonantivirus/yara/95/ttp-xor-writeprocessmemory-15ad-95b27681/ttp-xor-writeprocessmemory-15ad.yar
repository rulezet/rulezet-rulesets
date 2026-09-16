rule TTP_XOR_WriteProcessMemory_15ad {
  strings:
    $key_15ad = { 42 df [2] 70 fd [2] 76 c8 [2] 58 c8 [2] 67 d4 }

  condition:
    any of them
}