rule TTP_XOR_WriteProcessMemory_d823 {
  strings:
    $key_d823 = { 8f 51 [2] bd 73 [2] bb 46 [2] 95 46 [2] aa 5a }

  condition:
    any of them
}