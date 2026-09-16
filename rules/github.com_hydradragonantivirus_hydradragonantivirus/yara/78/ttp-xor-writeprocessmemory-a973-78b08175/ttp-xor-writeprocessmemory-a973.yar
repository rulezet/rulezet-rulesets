rule TTP_XOR_WriteProcessMemory_a973 {
  strings:
    $key_a973 = { fe 01 [2] cc 23 [2] ca 16 [2] e4 16 [2] db 0a }

  condition:
    any of them
}