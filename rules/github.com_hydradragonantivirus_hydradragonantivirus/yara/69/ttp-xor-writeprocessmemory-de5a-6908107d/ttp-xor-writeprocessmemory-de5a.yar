rule TTP_XOR_WriteProcessMemory_de5a {
  strings:
    $key_de5a = { 89 28 [2] bb 0a [2] bd 3f [2] 93 3f [2] ac 23 }

  condition:
    any of them
}