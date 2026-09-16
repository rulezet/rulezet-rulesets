rule TTP_XOR_WriteProcessMemory_d8ec {
  strings:
    $key_d8ec = { 8f 9e [2] bd bc [2] bb 89 [2] 95 89 [2] aa 95 }

  condition:
    any of them
}