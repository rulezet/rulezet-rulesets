rule TTP_XOR_WriteProcessMemory_de56 {
  strings:
    $key_de56 = { 89 24 [2] bb 06 [2] bd 33 [2] 93 33 [2] ac 2f }

  condition:
    any of them
}