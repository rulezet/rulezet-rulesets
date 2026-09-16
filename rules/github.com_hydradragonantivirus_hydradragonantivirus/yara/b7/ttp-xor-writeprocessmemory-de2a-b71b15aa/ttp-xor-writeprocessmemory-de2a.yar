rule TTP_XOR_WriteProcessMemory_de2a {
  strings:
    $key_de2a = { 89 58 [2] bb 7a [2] bd 4f [2] 93 4f [2] ac 53 }

  condition:
    any of them
}