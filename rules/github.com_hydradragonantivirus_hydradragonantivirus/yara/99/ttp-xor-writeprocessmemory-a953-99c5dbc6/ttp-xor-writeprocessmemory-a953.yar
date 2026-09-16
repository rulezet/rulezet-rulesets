rule TTP_XOR_WriteProcessMemory_a953 {
  strings:
    $key_a953 = { fe 21 [2] cc 03 [2] ca 36 [2] e4 36 [2] db 2a }

  condition:
    any of them
}