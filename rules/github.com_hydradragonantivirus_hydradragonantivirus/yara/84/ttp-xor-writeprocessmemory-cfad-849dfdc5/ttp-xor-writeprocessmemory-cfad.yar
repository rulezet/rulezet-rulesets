rule TTP_XOR_WriteProcessMemory_cfad {
  strings:
    $key_cfad = { 98 df [2] aa fd [2] ac c8 [2] 82 c8 [2] bd d4 }

  condition:
    any of them
}