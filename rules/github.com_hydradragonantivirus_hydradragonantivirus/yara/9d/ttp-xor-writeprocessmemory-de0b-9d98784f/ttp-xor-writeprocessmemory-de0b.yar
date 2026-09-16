rule TTP_XOR_WriteProcessMemory_de0b {
  strings:
    $key_de0b = { 89 79 [2] bb 5b [2] bd 6e [2] 93 6e [2] ac 72 }

  condition:
    any of them
}