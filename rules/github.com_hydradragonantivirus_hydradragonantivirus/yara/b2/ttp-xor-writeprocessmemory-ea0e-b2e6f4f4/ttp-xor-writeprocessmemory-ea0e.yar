rule TTP_XOR_WriteProcessMemory_ea0e {
  strings:
    $key_ea0e = { bd 7c [2] 8f 5e [2] 89 6b [2] a7 6b [2] 98 77 }

  condition:
    any of them
}