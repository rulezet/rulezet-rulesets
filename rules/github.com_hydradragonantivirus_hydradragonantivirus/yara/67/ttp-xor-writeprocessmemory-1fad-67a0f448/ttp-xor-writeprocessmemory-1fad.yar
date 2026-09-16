rule TTP_XOR_WriteProcessMemory_1fad {
  strings:
    $key_1fad = { 48 df [2] 7a fd [2] 7c c8 [2] 52 c8 [2] 6d d4 }

  condition:
    any of them
}