rule TTP_XOR_WriteProcessMemory_a933 {
  strings:
    $key_a933 = { fe 41 [2] cc 63 [2] ca 56 [2] e4 56 [2] db 4a }

  condition:
    any of them
}