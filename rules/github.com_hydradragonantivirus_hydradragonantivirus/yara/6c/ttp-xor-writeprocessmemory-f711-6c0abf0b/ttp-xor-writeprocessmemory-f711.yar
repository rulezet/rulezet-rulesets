rule TTP_XOR_WriteProcessMemory_f711 {
  strings:
    $key_f711 = { a0 63 [2] 92 41 [2] 94 74 [2] ba 74 [2] 85 68 }

  condition:
    any of them
}