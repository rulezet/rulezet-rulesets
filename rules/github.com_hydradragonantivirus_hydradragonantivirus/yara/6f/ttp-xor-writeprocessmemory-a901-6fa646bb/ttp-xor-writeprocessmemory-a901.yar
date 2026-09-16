rule TTP_XOR_WriteProcessMemory_a901 {
  strings:
    $key_a901 = { fe 73 [2] cc 51 [2] ca 64 [2] e4 64 [2] db 78 }

  condition:
    any of them
}