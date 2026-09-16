rule TTP_XOR_WriteProcessMemory_53ad {
  strings:
    $key_53ad = { 04 df [2] 36 fd [2] 30 c8 [2] 1e c8 [2] 21 d4 }

  condition:
    any of them
}