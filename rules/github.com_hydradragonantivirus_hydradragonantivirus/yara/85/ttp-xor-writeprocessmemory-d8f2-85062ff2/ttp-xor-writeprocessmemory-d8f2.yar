rule TTP_XOR_WriteProcessMemory_d8f2 {
  strings:
    $key_d8f2 = { 8f 80 [2] bd a2 [2] bb 97 [2] 95 97 [2] aa 8b }

  condition:
    any of them
}