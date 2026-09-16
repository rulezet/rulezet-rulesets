rule TTP_XOR_WriteProcessMemory_de06 {
  strings:
    $key_de06 = { 89 74 [2] bb 56 [2] bd 63 [2] 93 63 [2] ac 7f }

  condition:
    any of them
}