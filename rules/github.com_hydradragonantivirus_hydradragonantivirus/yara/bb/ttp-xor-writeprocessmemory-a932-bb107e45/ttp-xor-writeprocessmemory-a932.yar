rule TTP_XOR_WriteProcessMemory_a932 {
  strings:
    $key_a932 = { fe 40 [2] cc 62 [2] ca 57 [2] e4 57 [2] db 4b }

  condition:
    any of them
}