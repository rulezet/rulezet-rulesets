rule TTP_XOR_WriteProcessMemory_d863 {
  strings:
    $key_d863 = { 8f 11 [2] bd 33 [2] bb 06 [2] 95 06 [2] aa 1a }

  condition:
    any of them
}