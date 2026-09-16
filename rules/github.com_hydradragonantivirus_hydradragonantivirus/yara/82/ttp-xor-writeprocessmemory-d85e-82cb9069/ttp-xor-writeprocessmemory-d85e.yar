rule TTP_XOR_WriteProcessMemory_d85e {
  strings:
    $key_d85e = { 8f 2c [2] bd 0e [2] bb 3b [2] 95 3b [2] aa 27 }

  condition:
    any of them
}