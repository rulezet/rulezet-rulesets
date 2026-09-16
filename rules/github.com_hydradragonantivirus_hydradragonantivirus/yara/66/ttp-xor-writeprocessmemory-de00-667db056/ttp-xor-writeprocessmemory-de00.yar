rule TTP_XOR_WriteProcessMemory_de00 {
  strings:
    $key_de00 = { 89 72 [2] bb 50 [2] bd 65 [2] 93 65 [2] ac 79 }

  condition:
    any of them
}