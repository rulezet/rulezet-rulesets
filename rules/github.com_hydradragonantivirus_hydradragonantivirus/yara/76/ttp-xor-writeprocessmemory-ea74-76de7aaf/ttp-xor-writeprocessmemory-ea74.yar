rule TTP_XOR_WriteProcessMemory_ea74 {
  strings:
    $key_ea74 = { bd 06 [2] 8f 24 [2] 89 11 [2] a7 11 [2] 98 0d }

  condition:
    any of them
}