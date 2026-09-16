rule TTP_XOR_WriteProcessMemory_de7f {
  strings:
    $key_de7f = { 89 0d [2] bb 2f [2] bd 1a [2] 93 1a [2] ac 06 }

  condition:
    any of them
}