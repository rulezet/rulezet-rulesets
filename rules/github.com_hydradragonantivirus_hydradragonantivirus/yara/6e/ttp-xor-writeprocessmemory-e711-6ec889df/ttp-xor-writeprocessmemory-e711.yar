rule TTP_XOR_WriteProcessMemory_e711 {
  strings:
    $key_e711 = { b0 63 [2] 82 41 [2] 84 74 [2] aa 74 [2] 95 68 }

  condition:
    any of them
}