rule TTP_XOR_WriteProcessMemory_ea70 {
  strings:
    $key_ea70 = { bd 02 [2] 8f 20 [2] 89 15 [2] a7 15 [2] 98 09 }

  condition:
    any of them
}