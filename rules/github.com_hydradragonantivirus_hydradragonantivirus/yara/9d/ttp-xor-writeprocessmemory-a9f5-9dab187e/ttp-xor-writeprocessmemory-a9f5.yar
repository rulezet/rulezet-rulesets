rule TTP_XOR_WriteProcessMemory_a9f5 {
  strings:
    $key_a9f5 = { fe 87 [2] cc a5 [2] ca 90 [2] e4 90 [2] db 8c }

  condition:
    any of them
}