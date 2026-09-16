rule TTP_XOR_WriteProcessMemory_0fad {
  strings:
    $key_0fad = { 58 df [2] 6a fd [2] 6c c8 [2] 42 c8 [2] 7d d4 }

  condition:
    any of them
}