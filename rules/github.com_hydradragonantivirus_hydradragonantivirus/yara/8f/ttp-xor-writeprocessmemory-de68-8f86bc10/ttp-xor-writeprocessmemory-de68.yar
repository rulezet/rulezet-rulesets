rule TTP_XOR_WriteProcessMemory_de68 {
  strings:
    $key_de68 = { 89 1a [2] bb 38 [2] bd 0d [2] 93 0d [2] ac 11 }

  condition:
    any of them
}