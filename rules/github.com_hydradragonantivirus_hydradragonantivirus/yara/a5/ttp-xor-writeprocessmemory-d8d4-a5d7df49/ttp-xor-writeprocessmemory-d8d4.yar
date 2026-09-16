rule TTP_XOR_WriteProcessMemory_d8d4 {
  strings:
    $key_d8d4 = { 8f a6 [2] bd 84 [2] bb b1 [2] 95 b1 [2] aa ad }

  condition:
    any of them
}