rule TTP_XOR_WriteProcessMemory_d86e {
  strings:
    $key_d86e = { 8f 1c [2] bd 3e [2] bb 0b [2] 95 0b [2] aa 17 }

  condition:
    any of them
}