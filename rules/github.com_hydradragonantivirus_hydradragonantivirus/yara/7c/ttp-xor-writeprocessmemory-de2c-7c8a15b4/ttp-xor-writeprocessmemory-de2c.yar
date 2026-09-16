rule TTP_XOR_WriteProcessMemory_de2c {
  strings:
    $key_de2c = { 89 5e [2] bb 7c [2] bd 49 [2] 93 49 [2] ac 55 }

  condition:
    any of them
}