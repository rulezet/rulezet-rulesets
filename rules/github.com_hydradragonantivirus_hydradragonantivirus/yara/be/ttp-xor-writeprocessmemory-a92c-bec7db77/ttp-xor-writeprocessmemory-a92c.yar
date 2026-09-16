rule TTP_XOR_WriteProcessMemory_a92c {
  strings:
    $key_a92c = { fe 5e [2] cc 7c [2] ca 49 [2] e4 49 [2] db 55 }

  condition:
    any of them
}