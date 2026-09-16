rule TTP_XOR_WriteProcessMemory_d872 {
  strings:
    $key_d872 = { 8f 00 [2] bd 22 [2] bb 17 [2] 95 17 [2] aa 0b }

  condition:
    any of them
}