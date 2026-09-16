rule TTP_XOR_WriteProcessMemory_6fad {
  strings:
    $key_6fad = { 38 df [2] 0a fd [2] 0c c8 [2] 22 c8 [2] 1d d4 }

  condition:
    any of them
}