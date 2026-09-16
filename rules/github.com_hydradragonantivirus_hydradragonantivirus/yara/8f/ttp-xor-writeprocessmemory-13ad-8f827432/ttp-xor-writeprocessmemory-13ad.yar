rule TTP_XOR_WriteProcessMemory_13ad {
  strings:
    $key_13ad = { 44 df [2] 76 fd [2] 70 c8 [2] 5e c8 [2] 61 d4 }

  condition:
    any of them
}