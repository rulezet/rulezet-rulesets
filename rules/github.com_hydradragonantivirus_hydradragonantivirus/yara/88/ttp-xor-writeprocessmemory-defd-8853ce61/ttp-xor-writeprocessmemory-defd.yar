rule TTP_XOR_WriteProcessMemory_defd {
  strings:
    $key_defd = { 89 8f [2] bb ad [2] bd 98 [2] 93 98 [2] ac 84 }

  condition:
    any of them
}