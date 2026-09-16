rule TTP_XOR_WriteProcessMemory_de4b {
  strings:
    $key_de4b = { 89 39 [2] bb 1b [2] bd 2e [2] 93 2e [2] ac 32 }

  condition:
    any of them
}