rule TTP_XOR_WriteProcessMemory_5fad {
  strings:
    $key_5fad = { 08 df [2] 3a fd [2] 3c c8 [2] 12 c8 [2] 2d d4 }

  condition:
    any of them
}