rule TTP_XOR_WriteProcessMemory_a9f8 {
  strings:
    $key_a9f8 = { fe 8a [2] cc a8 [2] ca 9d [2] e4 9d [2] db 81 }

  condition:
    any of them
}