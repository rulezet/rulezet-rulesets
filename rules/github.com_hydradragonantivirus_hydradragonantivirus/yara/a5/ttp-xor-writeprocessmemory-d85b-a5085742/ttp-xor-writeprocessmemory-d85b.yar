rule TTP_XOR_WriteProcessMemory_d85b {
  strings:
    $key_d85b = { 8f 29 [2] bd 0b [2] bb 3e [2] 95 3e [2] aa 22 }

  condition:
    any of them
}