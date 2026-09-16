rule TTP_XOR_WriteProcessMemory_a916 {
  strings:
    $key_a916 = { fe 64 [2] cc 46 [2] ca 73 [2] e4 73 [2] db 6f }

  condition:
    any of them
}