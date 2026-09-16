rule TTP_XOR_WriteProcessMemory_d84c {
  strings:
    $key_d84c = { 8f 3e [2] bd 1c [2] bb 29 [2] 95 29 [2] aa 35 }

  condition:
    any of them
}