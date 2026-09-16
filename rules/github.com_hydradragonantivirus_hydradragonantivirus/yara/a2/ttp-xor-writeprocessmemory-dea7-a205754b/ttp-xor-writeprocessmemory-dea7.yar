rule TTP_XOR_WriteProcessMemory_dea7 {
  strings:
    $key_dea7 = { 89 d5 [2] bb f7 [2] bd c2 [2] 93 c2 [2] ac de }

  condition:
    any of them
}