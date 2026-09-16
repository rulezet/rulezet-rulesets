rule TTP_XOR_WriteProcessMemory_de5b {
  strings:
    $key_de5b = { 89 29 [2] bb 0b [2] bd 3e [2] 93 3e [2] ac 22 }

  condition:
    any of them
}