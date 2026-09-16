rule TTP_XOR_WriteProcessMemory_a936 {
  strings:
    $key_a936 = { fe 44 [2] cc 66 [2] ca 53 [2] e4 53 [2] db 4f }

  condition:
    any of them
}