rule TTP_XOR_WriteProcessMemory_de7c {
  strings:
    $key_de7c = { 89 0e [2] bb 2c [2] bd 19 [2] 93 19 [2] ac 05 }

  condition:
    any of them
}