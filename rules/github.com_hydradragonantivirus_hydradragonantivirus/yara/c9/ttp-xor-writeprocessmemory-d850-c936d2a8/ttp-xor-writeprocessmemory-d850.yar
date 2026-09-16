rule TTP_XOR_WriteProcessMemory_d850 {
  strings:
    $key_d850 = { 8f 22 [2] bd 00 [2] bb 35 [2] 95 35 [2] aa 29 }

  condition:
    any of them
}