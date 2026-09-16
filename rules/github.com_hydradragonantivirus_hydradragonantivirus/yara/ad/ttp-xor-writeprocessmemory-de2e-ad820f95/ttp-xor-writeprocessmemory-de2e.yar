rule TTP_XOR_WriteProcessMemory_de2e {
  strings:
    $key_de2e = { 89 5c [2] bb 7e [2] bd 4b [2] 93 4b [2] ac 57 }

  condition:
    any of them
}