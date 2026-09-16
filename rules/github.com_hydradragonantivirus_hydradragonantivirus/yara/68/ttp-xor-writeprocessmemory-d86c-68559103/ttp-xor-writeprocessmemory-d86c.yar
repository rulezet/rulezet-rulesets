rule TTP_XOR_WriteProcessMemory_d86c {
  strings:
    $key_d86c = { 8f 1e [2] bd 3c [2] bb 09 [2] 95 09 [2] aa 15 }

  condition:
    any of them
}