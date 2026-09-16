rule TTP_XOR_WriteProcessMemory_d4ad {
  strings:
    $key_d4ad = { 83 df [2] b1 fd [2] b7 c8 [2] 99 c8 [2] a6 d4 }

  condition:
    any of them
}