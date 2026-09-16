rule TTP_XOR_WriteProcessMemory_2711 {
  strings:
    $key_2711 = { 70 63 [2] 42 41 [2] 44 74 [2] 6a 74 [2] 55 68 }

  condition:
    any of them
}