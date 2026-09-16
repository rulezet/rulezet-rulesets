rule TTP_XOR_WriteProcessMemory_de1b {
  strings:
    $key_de1b = { 89 69 [2] bb 4b [2] bd 7e [2] 93 7e [2] ac 62 }

  condition:
    any of them
}