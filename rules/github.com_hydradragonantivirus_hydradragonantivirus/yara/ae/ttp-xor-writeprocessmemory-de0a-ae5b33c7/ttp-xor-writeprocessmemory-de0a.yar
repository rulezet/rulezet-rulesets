rule TTP_XOR_WriteProcessMemory_de0a {
  strings:
    $key_de0a = { 89 78 [2] bb 5a [2] bd 6f [2] 93 6f [2] ac 73 }

  condition:
    any of them
}