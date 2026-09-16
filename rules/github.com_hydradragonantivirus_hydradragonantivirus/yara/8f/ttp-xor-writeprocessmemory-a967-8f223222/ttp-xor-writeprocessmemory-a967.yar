rule TTP_XOR_WriteProcessMemory_a967 {
  strings:
    $key_a967 = { fe 15 [2] cc 37 [2] ca 02 [2] e4 02 [2] db 1e }

  condition:
    any of them
}