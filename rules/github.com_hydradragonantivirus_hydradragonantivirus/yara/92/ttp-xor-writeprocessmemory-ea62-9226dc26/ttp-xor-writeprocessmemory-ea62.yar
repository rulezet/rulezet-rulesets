rule TTP_XOR_WriteProcessMemory_ea62 {
  strings:
    $key_ea62 = { bd 10 [2] 8f 32 [2] 89 07 [2] a7 07 [2] 98 1b }

  condition:
    any of them
}