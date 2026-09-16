rule TTP_XOR_WriteProcessMemory_beba {
  strings:
    $key_beba = { e9 c8 [2] db ea [2] dd df [2] f3 df [2] cc c3 }

  condition:
    any of them
}