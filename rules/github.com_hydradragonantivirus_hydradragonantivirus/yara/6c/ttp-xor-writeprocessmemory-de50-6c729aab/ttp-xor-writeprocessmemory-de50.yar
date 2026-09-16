rule TTP_XOR_WriteProcessMemory_de50 {
  strings:
    $key_de50 = { 89 22 [2] bb 00 [2] bd 35 [2] 93 35 [2] ac 29 }

  condition:
    any of them
}