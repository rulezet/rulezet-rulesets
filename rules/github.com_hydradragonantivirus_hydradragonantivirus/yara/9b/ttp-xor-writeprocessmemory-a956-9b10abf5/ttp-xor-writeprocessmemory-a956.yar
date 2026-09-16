rule TTP_XOR_WriteProcessMemory_a956 {
  strings:
    $key_a956 = { fe 24 [2] cc 06 [2] ca 33 [2] e4 33 [2] db 2f }

  condition:
    any of them
}