rule TTP_XOR_WriteProcessMemory_ea57 {
  strings:
    $key_ea57 = { bd 25 [2] 8f 07 [2] 89 32 [2] a7 32 [2] 98 2e }

  condition:
    any of them
}