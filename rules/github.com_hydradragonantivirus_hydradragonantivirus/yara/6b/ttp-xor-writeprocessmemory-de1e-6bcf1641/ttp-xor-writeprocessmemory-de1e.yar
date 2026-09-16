rule TTP_XOR_WriteProcessMemory_de1e {
  strings:
    $key_de1e = { 89 6c [2] bb 4e [2] bd 7b [2] 93 7b [2] ac 67 }

  condition:
    any of them
}