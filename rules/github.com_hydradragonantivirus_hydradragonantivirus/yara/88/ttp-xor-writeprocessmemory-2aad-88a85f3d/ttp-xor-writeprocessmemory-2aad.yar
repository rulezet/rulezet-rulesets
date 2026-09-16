rule TTP_XOR_WriteProcessMemory_2aad {
  strings:
    $key_2aad = { 7d df [2] 4f fd [2] 49 c8 [2] 67 c8 [2] 58 d4 }

  condition:
    any of them
}