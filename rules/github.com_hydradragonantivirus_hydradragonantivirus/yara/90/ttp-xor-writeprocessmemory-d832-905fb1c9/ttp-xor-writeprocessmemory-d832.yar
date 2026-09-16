rule TTP_XOR_WriteProcessMemory_d832 {
  strings:
    $key_d832 = { 8f 40 [2] bd 62 [2] bb 57 [2] 95 57 [2] aa 4b }

  condition:
    any of them
}