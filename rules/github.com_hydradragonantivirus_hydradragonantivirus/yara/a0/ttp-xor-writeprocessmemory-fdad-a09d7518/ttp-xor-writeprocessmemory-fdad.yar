rule TTP_XOR_WriteProcessMemory_fdad {
  strings:
    $key_fdad = { aa df [2] 98 fd [2] 9e c8 [2] b0 c8 [2] 8f d4 }

  condition:
    any of them
}