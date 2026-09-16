rule TTP_XOR_WriteProcessMemory_ea7b {
  strings:
    $key_ea7b = { bd 09 [2] 8f 2b [2] 89 1e [2] a7 1e [2] 98 02 }

  condition:
    any of them
}