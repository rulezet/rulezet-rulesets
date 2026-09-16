rule TTP_XOR_WriteProcessMemory_a976 {
  strings:
    $key_a976 = { fe 04 [2] cc 26 [2] ca 13 [2] e4 13 [2] db 0f }

  condition:
    any of them
}