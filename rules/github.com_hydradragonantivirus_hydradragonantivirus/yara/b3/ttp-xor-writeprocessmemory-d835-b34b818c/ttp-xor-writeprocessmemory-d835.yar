rule TTP_XOR_WriteProcessMemory_d835 {
  strings:
    $key_d835 = { 8f 47 [2] bd 65 [2] bb 50 [2] 95 50 [2] aa 4c }

  condition:
    any of them
}