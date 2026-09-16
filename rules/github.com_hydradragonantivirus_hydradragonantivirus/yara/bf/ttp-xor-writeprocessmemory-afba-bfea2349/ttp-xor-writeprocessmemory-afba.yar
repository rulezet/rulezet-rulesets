rule TTP_XOR_WriteProcessMemory_afba {
  strings:
    $key_afba = { f8 c8 [2] ca ea [2] cc df [2] e2 df [2] dd c3 }

  condition:
    any of them
}