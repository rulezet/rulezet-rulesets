rule TTP_XOR_WriteProcessMemory_a965 {
  strings:
    $key_a965 = { fe 17 [2] cc 35 [2] ca 00 [2] e4 00 [2] db 1c }

  condition:
    any of them
}