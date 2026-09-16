rule TTP_XOR_WriteProcessMemory_a94c {
  strings:
    $key_a94c = { fe 3e [2] cc 1c [2] ca 29 [2] e4 29 [2] db 35 }

  condition:
    any of them
}