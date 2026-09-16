rule TTP_XOR_WriteProcessMemory_ea2e {
  strings:
    $key_ea2e = { bd 5c [2] 8f 7e [2] 89 4b [2] a7 4b [2] 98 57 }

  condition:
    any of them
}