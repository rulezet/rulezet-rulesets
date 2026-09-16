rule TTP_XOR_WriteProcessMemory_ea6b {
  strings:
    $key_ea6b = { bd 19 [2] 8f 3b [2] 89 0e [2] a7 0e [2] 98 12 }

  condition:
    any of them
}