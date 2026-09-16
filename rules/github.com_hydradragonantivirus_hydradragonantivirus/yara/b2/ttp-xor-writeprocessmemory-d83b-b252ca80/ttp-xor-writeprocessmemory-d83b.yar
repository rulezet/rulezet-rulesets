rule TTP_XOR_WriteProcessMemory_d83b {
  strings:
    $key_d83b = { 8f 49 [2] bd 6b [2] bb 5e [2] 95 5e [2] aa 42 }

  condition:
    any of them
}