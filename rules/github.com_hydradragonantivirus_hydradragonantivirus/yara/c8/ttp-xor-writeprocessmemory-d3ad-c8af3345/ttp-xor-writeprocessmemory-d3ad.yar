rule TTP_XOR_WriteProcessMemory_d3ad {
  strings:
    $key_d3ad = { 84 df [2] b6 fd [2] b0 c8 [2] 9e c8 [2] a1 d4 }

  condition:
    any of them
}