rule TTP_XOR_WriteProcessMemory_ea7e {
  strings:
    $key_ea7e = { bd 0c [2] 8f 2e [2] 89 1b [2] a7 1b [2] 98 07 }

  condition:
    any of them
}