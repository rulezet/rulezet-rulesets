rule TTP_XOR_WriteProcessMemory_efad {
  strings:
    $key_efad = { b8 df [2] 8a fd [2] 8c c8 [2] a2 c8 [2] 9d d4 }

  condition:
    any of them
}