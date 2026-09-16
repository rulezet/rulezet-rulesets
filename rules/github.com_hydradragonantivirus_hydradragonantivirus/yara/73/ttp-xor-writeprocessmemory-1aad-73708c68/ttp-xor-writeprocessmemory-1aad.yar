rule TTP_XOR_WriteProcessMemory_1aad {
  strings:
    $key_1aad = { 4d df [2] 7f fd [2] 79 c8 [2] 57 c8 [2] 68 d4 }

  condition:
    any of them
}