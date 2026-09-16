rule TTP_XOR_WriteProcessMemory_e8ad {
  strings:
    $key_e8ad = { bf df [2] 8d fd [2] 8b c8 [2] a5 c8 [2] 9a d4 }

  condition:
    any of them
}