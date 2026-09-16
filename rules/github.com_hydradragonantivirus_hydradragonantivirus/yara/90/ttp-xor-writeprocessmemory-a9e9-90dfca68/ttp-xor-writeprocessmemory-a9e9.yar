rule TTP_XOR_WriteProcessMemory_a9e9 {
  strings:
    $key_a9e9 = { fe 9b [2] cc b9 [2] ca 8c [2] e4 8c [2] db 90 }

  condition:
    any of them
}