rule TTP_XOR_WriteProcessMemory_d802 {
  strings:
    $key_d802 = { 8f 70 [2] bd 52 [2] bb 67 [2] 95 67 [2] aa 7b }

  condition:
    any of them
}