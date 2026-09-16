rule TTP_XOR_WriteProcessMemory_a963 {
  strings:
    $key_a963 = { fe 11 [2] cc 33 [2] ca 06 [2] e4 06 [2] db 1a }

  condition:
    any of them
}