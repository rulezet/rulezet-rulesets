rule TTP_XOR_WriteProcessMemory_de1a {
  strings:
    $key_de1a = { 89 68 [2] bb 4a [2] bd 7f [2] 93 7f [2] ac 63 }

  condition:
    any of them
}