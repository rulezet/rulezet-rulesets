rule TTP_XOR_WriteProcessMemory_d873 {
  strings:
    $key_d873 = { 8f 01 [2] bd 23 [2] bb 16 [2] 95 16 [2] aa 0a }

  condition:
    any of them
}