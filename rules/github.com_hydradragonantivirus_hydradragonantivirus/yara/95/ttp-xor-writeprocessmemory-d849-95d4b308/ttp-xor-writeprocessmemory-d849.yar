rule TTP_XOR_WriteProcessMemory_d849 {
  strings:
    $key_d849 = { 8f 3b [2] bd 19 [2] bb 2c [2] 95 2c [2] aa 30 }

  condition:
    any of them
}