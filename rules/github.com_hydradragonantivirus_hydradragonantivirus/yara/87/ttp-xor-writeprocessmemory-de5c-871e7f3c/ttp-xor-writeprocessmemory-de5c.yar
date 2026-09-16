rule TTP_XOR_WriteProcessMemory_de5c {
  strings:
    $key_de5c = { 89 2e [2] bb 0c [2] bd 39 [2] 93 39 [2] ac 25 }

  condition:
    any of them
}