rule TTP_XOR_WriteProcessMemory_a912 {
  strings:
    $key_a912 = { fe 60 [2] cc 42 [2] ca 77 [2] e4 77 [2] db 6b }

  condition:
    any of them
}