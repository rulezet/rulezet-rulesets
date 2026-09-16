rule TTP_XOR_WriteProcessMemory_ea22 {
  strings:
    $key_ea22 = { bd 50 [2] 8f 72 [2] 89 47 [2] a7 47 [2] 98 5b }

  condition:
    any of them
}