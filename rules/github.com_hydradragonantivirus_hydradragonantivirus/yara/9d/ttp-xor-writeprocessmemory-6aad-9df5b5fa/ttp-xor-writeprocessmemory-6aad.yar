rule TTP_XOR_WriteProcessMemory_6aad {
  strings:
    $key_6aad = { 3d df [2] 0f fd [2] 09 c8 [2] 27 c8 [2] 18 d4 }

  condition:
    any of them
}