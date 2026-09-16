rule TTP_XOR_WriteProcessMemory_f057 {
  strings:
    $key_f057 = { a7 25 [2] 95 07 [2] 93 32 [2] bd 32 [2] 82 2e }

  condition:
    any of them
}