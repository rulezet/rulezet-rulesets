rule TTP_XOR_WriteProcessMemory_de38 {
  strings:
    $key_de38 = { 89 4a [2] bb 68 [2] bd 5d [2] 93 5d [2] ac 41 }

  condition:
    any of them
}