rule TTP_XOR_WriteProcessMemory_ea02 {
  strings:
    $key_ea02 = { bd 70 [2] 8f 52 [2] 89 67 [2] a7 67 [2] 98 7b }

  condition:
    any of them
}