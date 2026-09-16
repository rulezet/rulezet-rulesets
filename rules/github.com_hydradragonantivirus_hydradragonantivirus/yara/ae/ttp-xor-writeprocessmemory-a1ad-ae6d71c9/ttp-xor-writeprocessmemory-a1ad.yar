rule TTP_XOR_WriteProcessMemory_a1ad {
  strings:
    $key_a1ad = { f6 df [2] c4 fd [2] c2 c8 [2] ec c8 [2] d3 d4 }

  condition:
    any of them
}