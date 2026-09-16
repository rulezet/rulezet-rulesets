rule TTP_XOR_WriteProcessMemory_defc {
  strings:
    $key_defc = { 89 8e [2] bb ac [2] bd 99 [2] 93 99 [2] ac 85 }

  condition:
    any of them
}