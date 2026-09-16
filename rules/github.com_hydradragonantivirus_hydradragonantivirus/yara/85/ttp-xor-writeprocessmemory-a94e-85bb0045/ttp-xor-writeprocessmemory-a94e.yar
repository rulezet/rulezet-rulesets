rule TTP_XOR_WriteProcessMemory_a94e {
  strings:
    $key_a94e = { fe 3c [2] cc 1e [2] ca 2b [2] e4 2b [2] db 37 }

  condition:
    any of them
}