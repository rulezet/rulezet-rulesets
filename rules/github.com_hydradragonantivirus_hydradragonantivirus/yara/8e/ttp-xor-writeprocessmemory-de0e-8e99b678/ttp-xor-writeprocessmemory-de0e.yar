rule TTP_XOR_WriteProcessMemory_de0e {
  strings:
    $key_de0e = { 89 7c [2] bb 5e [2] bd 6b [2] 93 6b [2] ac 77 }

  condition:
    any of them
}