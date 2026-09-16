rule TTP_XOR_WriteProcessMemory_dea3 {
  strings:
    $key_dea3 = { 89 d1 [2] bb f3 [2] bd c6 [2] 93 c6 [2] ac da }

  condition:
    any of them
}