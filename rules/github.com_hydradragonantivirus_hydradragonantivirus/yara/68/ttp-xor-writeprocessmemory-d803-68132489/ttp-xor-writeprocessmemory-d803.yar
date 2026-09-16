rule TTP_XOR_WriteProcessMemory_d803 {
  strings:
    $key_d803 = { 8f 71 [2] bd 53 [2] bb 66 [2] 95 66 [2] aa 7a }

  condition:
    any of them
}