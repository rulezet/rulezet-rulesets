rule TTP_XOR_WriteProcessMemory_fcad {
  strings:
    $key_fcad = { ab df [2] 99 fd [2] 9f c8 [2] b1 c8 [2] 8e d4 }

  condition:
    any of them
}