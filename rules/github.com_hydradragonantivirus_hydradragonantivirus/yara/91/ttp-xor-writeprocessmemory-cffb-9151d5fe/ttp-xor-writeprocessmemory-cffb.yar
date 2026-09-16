rule TTP_XOR_WriteProcessMemory_cffb {
  strings:
    $key_cffb = { 98 89 [2] aa ab [2] ac 9e [2] 82 9e [2] bd 82 }

  condition:
    any of them
}