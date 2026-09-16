rule TTP_XOR_WriteProcessMemory_dead {
  strings:
    $key_dead = { 89 df [2] bb fd [2] bd c8 [2] 93 c8 [2] ac d4 }

  condition:
    any of them
}