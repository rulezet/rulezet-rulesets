rule TTP_XOR_WriteProcessMemory_51ad {
  strings:
    $key_51ad = { 06 df [2] 34 fd [2] 32 c8 [2] 1c c8 [2] 23 d4 }

  condition:
    any of them
}