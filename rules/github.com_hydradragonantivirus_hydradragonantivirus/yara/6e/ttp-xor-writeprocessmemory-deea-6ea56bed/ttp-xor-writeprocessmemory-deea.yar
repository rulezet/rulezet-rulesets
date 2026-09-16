rule TTP_XOR_WriteProcessMemory_deea {
  strings:
    $key_deea = { 89 98 [2] bb ba [2] bd 8f [2] 93 8f [2] ac 93 }

  condition:
    any of them
}