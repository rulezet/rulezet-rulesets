rule TTP_XOR_WriteProcessMemory_caad {
  strings:
    $key_caad = { 9d df [2] af fd [2] a9 c8 [2] 87 c8 [2] b8 d4 }

  condition:
    any of them
}