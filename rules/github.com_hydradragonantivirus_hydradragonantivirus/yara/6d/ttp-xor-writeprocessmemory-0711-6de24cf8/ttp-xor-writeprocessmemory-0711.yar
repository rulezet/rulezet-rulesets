rule TTP_XOR_WriteProcessMemory_0711 {
  strings:
    $key_0711 = { 50 63 [2] 62 41 [2] 64 74 [2] 4a 74 [2] 75 68 }

  condition:
    any of them
}