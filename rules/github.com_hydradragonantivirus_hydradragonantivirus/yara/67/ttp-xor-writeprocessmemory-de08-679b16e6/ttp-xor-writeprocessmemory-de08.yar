rule TTP_XOR_WriteProcessMemory_de08 {
  strings:
    $key_de08 = { 89 7a [2] bb 58 [2] bd 6d [2] 93 6d [2] ac 71 }

  condition:
    any of them
}