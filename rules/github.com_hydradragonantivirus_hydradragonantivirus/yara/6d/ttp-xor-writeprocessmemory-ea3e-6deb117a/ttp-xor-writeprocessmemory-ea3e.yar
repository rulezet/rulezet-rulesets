rule TTP_XOR_WriteProcessMemory_ea3e {
  strings:
    $key_ea3e = { bd 4c [2] 8f 6e [2] 89 5b [2] a7 5b [2] 98 47 }

  condition:
    any of them
}