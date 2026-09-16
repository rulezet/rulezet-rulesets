rule TTP_XOR_WriteProcessMemory_d8d1 {
  strings:
    $key_d8d1 = { 8f a3 [2] bd 81 [2] bb b4 [2] 95 b4 [2] aa a8 }

  condition:
    any of them
}