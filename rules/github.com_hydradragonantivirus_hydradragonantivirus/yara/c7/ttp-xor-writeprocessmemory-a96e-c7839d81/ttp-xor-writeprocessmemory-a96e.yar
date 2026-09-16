rule TTP_XOR_WriteProcessMemory_a96e {
  strings:
    $key_a96e = { fe 1c [2] cc 3e [2] ca 0b [2] e4 0b [2] db 17 }

  condition:
    any of them
}