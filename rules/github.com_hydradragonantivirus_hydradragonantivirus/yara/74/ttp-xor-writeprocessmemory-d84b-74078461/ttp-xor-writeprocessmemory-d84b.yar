rule TTP_XOR_WriteProcessMemory_d84b {
  strings:
    $key_d84b = { 8f 39 [2] bd 1b [2] bb 2e [2] 95 2e [2] aa 32 }

  condition:
    any of them
}