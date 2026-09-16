rule TTP_XOR_WriteProcessMemory_de6e {
  strings:
    $key_de6e = { 89 1c [2] bb 3e [2] bd 0b [2] 93 0b [2] ac 17 }

  condition:
    any of them
}