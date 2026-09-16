rule TTP_XOR_WriteProcessMemory_de5d {
  strings:
    $key_de5d = { 89 2f [2] bb 0d [2] bd 38 [2] 93 38 [2] ac 24 }

  condition:
    any of them
}