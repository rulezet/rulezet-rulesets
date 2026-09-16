rule TTP_XOR_WriteProcessMemory_eaeb {
  strings:
    $key_eaeb = { bd 99 [2] 8f bb [2] 89 8e [2] a7 8e [2] 98 92 }

  condition:
    any of them
}