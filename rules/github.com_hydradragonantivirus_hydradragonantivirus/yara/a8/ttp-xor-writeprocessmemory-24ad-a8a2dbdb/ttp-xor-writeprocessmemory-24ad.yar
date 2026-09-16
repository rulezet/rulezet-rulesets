rule TTP_XOR_WriteProcessMemory_24ad {
  strings:
    $key_24ad = { 73 df [2] 41 fd [2] 47 c8 [2] 69 c8 [2] 56 d4 }

  condition:
    any of them
}