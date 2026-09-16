rule TTP_XOR_WriteProcessMemory_de3b {
  strings:
    $key_de3b = { 89 49 [2] bb 6b [2] bd 5e [2] 93 5e [2] ac 42 }

  condition:
    any of them
}