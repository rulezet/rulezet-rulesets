rule TTP_XOR_WriteProcessMemory_d867 {
  strings:
    $key_d867 = { 8f 15 [2] bd 37 [2] bb 02 [2] 95 02 [2] aa 1e }

  condition:
    any of them
}