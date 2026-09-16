rule TTP_XOR_WriteProcessMemory_de73 {
  strings:
    $key_de73 = { 89 01 [2] bb 23 [2] bd 16 [2] 93 16 [2] ac 0a }

  condition:
    any of them
}