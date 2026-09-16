rule TTP_XOR_WriteProcessMemory_ea5c {
  strings:
    $key_ea5c = { bd 2e [2] 8f 0c [2] 89 39 [2] a7 39 [2] 98 25 }

  condition:
    any of them
}