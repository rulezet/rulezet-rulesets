rule TTP_XOR_WriteProcessMemory_de6c {
  strings:
    $key_de6c = { 89 1e [2] bb 3c [2] bd 09 [2] 93 09 [2] ac 15 }

  condition:
    any of them
}