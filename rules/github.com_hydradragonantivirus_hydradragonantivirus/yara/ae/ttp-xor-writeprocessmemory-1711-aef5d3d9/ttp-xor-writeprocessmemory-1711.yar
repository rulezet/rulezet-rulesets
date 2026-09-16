rule TTP_XOR_WriteProcessMemory_1711 {
  strings:
    $key_1711 = { 40 63 [2] 72 41 [2] 74 74 [2] 5a 74 [2] 65 68 }

  condition:
    any of them
}