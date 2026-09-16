rule TTP_XOR_WriteProcessMemory_de3c {
  strings:
    $key_de3c = { 89 4e [2] bb 6c [2] bd 59 [2] 93 59 [2] ac 45 }

  condition:
    any of them
}