rule TTP_XOR_WriteProcessMemory_a96c {
  strings:
    $key_a96c = { fe 1e [2] cc 3c [2] ca 09 [2] e4 09 [2] db 15 }

  condition:
    any of them
}