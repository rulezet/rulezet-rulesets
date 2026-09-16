rule TTP_XOR_WriteProcessMemory_de3e {
  strings:
    $key_de3e = { 89 4c [2] bb 6e [2] bd 5b [2] 93 5b [2] ac 47 }

  condition:
    any of them
}