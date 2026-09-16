rule TTP_XOR_WriteProcessMemory_deef {
  strings:
    $key_deef = { 89 9d [2] bb bf [2] bd 8a [2] 93 8a [2] ac 96 }

  condition:
    any of them
}