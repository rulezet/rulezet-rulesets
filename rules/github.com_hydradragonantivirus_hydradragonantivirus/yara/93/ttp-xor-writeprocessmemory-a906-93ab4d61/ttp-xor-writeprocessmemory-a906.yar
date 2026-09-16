rule TTP_XOR_WriteProcessMemory_a906 {
  strings:
    $key_a906 = { fe 74 [2] cc 56 [2] ca 63 [2] e4 63 [2] db 7f }

  condition:
    any of them
}