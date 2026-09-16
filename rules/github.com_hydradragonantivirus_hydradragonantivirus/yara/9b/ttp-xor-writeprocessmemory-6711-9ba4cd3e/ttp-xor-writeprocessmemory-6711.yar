rule TTP_XOR_WriteProcessMemory_6711 {
  strings:
    $key_6711 = { 30 63 [2] 02 41 [2] 04 74 [2] 2a 74 [2] 15 68 }

  condition:
    any of them
}