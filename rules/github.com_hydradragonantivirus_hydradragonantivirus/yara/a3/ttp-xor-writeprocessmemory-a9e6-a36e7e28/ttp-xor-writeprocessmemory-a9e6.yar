rule TTP_XOR_WriteProcessMemory_a9e6 {
  strings:
    $key_a9e6 = { fe 94 [2] cc b6 [2] ca 83 [2] e4 83 [2] db 9f }

  condition:
    any of them
}