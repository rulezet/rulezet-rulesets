rule TTP_XOR_WriteProcessMemory_b0ad {
  strings:
    $key_b0ad = { e7 df [2] d5 fd [2] d3 c8 [2] fd c8 [2] c2 d4 }

  condition:
    any of them
}