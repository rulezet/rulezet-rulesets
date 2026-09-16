rule TTP_XOR_WriteProcessMemory_a9f2 {
  strings:
    $key_a9f2 = { fe 80 [2] cc a2 [2] ca 97 [2] e4 97 [2] db 8b }

  condition:
    any of them
}