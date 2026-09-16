rule TTP_XOR_WriteProcessMemory_a924 {
  strings:
    $key_a924 = { fe 56 [2] cc 74 [2] ca 41 [2] e4 41 [2] db 5d }

  condition:
    any of them
}