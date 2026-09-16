rule TTP_XOR_WriteProcessMemory_ea63 {
  strings:
    $key_ea63 = { bd 11 [2] 8f 33 [2] 89 06 [2] a7 06 [2] 98 1a }

  condition:
    any of them
}