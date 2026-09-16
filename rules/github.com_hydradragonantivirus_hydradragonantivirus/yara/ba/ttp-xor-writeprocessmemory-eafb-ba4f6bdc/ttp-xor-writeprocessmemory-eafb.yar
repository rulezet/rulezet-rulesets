rule TTP_XOR_WriteProcessMemory_eafb {
  strings:
    $key_eafb = { bd 89 [2] 8f ab [2] 89 9e [2] a7 9e [2] 98 82 }

  condition:
    any of them
}