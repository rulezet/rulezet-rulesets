rule TTP_XOR_WriteProcessMemory_4fad {
  strings:
    $key_4fad = { 18 df [2] 2a fd [2] 2c c8 [2] 02 c8 [2] 3d d4 }

  condition:
    any of them
}