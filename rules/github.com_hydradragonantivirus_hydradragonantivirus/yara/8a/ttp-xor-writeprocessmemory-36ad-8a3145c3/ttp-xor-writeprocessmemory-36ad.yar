rule TTP_XOR_WriteProcessMemory_36ad {
  strings:
    $key_36ad = { 61 df [2] 53 fd [2] 55 c8 [2] 7b c8 [2] 44 d4 }

  condition:
    any of them
}