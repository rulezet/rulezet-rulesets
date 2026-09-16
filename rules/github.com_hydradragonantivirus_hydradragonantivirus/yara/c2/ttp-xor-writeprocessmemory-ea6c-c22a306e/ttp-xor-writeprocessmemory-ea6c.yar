rule TTP_XOR_WriteProcessMemory_ea6c {
  strings:
    $key_ea6c = { bd 1e [2] 8f 3c [2] 89 09 [2] a7 09 [2] 98 15 }

  condition:
    any of them
}