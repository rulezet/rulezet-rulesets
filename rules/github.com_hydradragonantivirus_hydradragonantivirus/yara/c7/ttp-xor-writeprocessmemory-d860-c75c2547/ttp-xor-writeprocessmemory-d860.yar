rule TTP_XOR_WriteProcessMemory_d860 {
  strings:
    $key_d860 = { 8f 12 [2] bd 30 [2] bb 05 [2] 95 05 [2] aa 19 }

  condition:
    any of them
}