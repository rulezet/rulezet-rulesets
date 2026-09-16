rule TTP_XOR_WriteProcessMemory_9711 {
  strings:
    $key_9711 = { c0 63 [2] f2 41 [2] f4 74 [2] da 74 [2] e5 68 }

  condition:
    any of them
}