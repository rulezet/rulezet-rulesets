rule TTP_XOR_WriteProcessMemory_d838 {
  strings:
    $key_d838 = { 8f 4a [2] bd 68 [2] bb 5d [2] 95 5d [2] aa 41 }

  condition:
    any of them
}