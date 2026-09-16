rule TTP_XOR_WriteProcessMemory_a9e2 {
  strings:
    $key_a9e2 = { fe 90 [2] cc b2 [2] ca 87 [2] e4 87 [2] db 9b }

  condition:
    any of them
}