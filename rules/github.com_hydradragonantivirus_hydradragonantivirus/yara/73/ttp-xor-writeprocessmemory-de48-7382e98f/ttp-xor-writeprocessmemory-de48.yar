rule TTP_XOR_WriteProcessMemory_de48 {
  strings:
    $key_de48 = { 89 3a [2] bb 18 [2] bd 2d [2] 93 2d [2] ac 31 }

  condition:
    any of them
}