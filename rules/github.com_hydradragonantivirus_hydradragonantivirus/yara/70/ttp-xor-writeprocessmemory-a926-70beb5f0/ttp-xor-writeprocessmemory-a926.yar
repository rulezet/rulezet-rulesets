rule TTP_XOR_WriteProcessMemory_a926 {
  strings:
    $key_a926 = { fe 54 [2] cc 76 [2] ca 43 [2] e4 43 [2] db 5f }

  condition:
    any of them
}