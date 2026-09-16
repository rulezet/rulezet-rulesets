rule TTP_XOR_WriteProcessMemory_d857 {
  strings:
    $key_d857 = { 8f 25 [2] bd 07 [2] bb 32 [2] 95 32 [2] aa 2e }

  condition:
    any of them
}