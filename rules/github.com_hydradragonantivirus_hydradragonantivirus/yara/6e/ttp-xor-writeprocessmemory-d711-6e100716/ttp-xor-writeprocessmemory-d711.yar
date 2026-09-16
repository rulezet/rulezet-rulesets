rule TTP_XOR_WriteProcessMemory_d711 {
  strings:
    $key_d711 = { 80 63 [2] b2 41 [2] b4 74 [2] 9a 74 [2] a5 68 }

  condition:
    any of them
}