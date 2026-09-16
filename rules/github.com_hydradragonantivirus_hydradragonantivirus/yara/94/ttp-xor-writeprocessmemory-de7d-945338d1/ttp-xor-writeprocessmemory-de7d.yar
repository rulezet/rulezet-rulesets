rule TTP_XOR_WriteProcessMemory_de7d {
  strings:
    $key_de7d = { 89 0f [2] bb 2d [2] bd 18 [2] 93 18 [2] ac 04 }

  condition:
    any of them
}