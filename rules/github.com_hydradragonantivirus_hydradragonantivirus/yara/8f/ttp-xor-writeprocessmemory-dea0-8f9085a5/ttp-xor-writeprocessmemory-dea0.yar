rule TTP_XOR_WriteProcessMemory_dea0 {
  strings:
    $key_dea0 = { 89 d2 [2] bb f0 [2] bd c5 [2] 93 c5 [2] ac d9 }

  condition:
    any of them
}