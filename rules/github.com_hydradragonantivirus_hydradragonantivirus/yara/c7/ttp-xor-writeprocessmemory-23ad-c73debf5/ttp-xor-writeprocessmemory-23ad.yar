rule TTP_XOR_WriteProcessMemory_23ad {
  strings:
    $key_23ad = { 74 df [2] 46 fd [2] 40 c8 [2] 6e c8 [2] 51 d4 }

  condition:
    any of them
}