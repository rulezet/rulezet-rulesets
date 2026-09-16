rule TTP_XOR_WriteProcessMemory_de72 {
  strings:
    $key_de72 = { 89 00 [2] bb 22 [2] bd 17 [2] 93 17 [2] ac 0b }

  condition:
    any of them
}