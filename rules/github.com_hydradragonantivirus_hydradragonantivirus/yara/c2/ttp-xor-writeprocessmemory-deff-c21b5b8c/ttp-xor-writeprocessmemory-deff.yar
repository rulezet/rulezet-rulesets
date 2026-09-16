rule TTP_XOR_WriteProcessMemory_deff {
  strings:
    $key_deff = { 89 8d [2] bb af [2] bd 9a [2] 93 9a [2] ac 86 }

  condition:
    any of them
}