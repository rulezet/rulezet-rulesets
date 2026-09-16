rule TTP_XOR_WriteProcessMemory_ea3c {
  strings:
    $key_ea3c = { bd 4e [2] 8f 6c [2] 89 59 [2] a7 59 [2] 98 45 }

  condition:
    any of them
}