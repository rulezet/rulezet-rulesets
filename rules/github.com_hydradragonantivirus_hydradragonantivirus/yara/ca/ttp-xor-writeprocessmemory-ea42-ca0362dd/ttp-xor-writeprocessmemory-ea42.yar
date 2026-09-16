rule TTP_XOR_WriteProcessMemory_ea42 {
  strings:
    $key_ea42 = { bd 30 [2] 8f 12 [2] 89 27 [2] a7 27 [2] 98 3b }

  condition:
    any of them
}