rule TTP_XOR_WriteProcessMemory_de22 {
  strings:
    $key_de22 = { 89 50 [2] bb 72 [2] bd 47 [2] 93 47 [2] ac 5b }

  condition:
    any of them
}