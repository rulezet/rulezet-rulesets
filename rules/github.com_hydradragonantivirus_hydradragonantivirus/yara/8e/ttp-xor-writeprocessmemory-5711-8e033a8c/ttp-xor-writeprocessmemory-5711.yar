rule TTP_XOR_WriteProcessMemory_5711 {
  strings:
    $key_5711 = { 00 63 [2] 32 41 [2] 34 74 [2] 1a 74 [2] 25 68 }

  condition:
    any of them
}