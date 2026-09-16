rule TTP_XOR_WriteProcessMemory_de5e {
  strings:
    $key_de5e = { 89 2c [2] bb 0e [2] bd 3b [2] 93 3b [2] ac 27 }

  condition:
    any of them
}