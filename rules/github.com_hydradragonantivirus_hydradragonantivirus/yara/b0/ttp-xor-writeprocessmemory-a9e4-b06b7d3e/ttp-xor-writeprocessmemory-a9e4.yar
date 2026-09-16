rule TTP_XOR_WriteProcessMemory_a9e4 {
  strings:
    $key_a9e4 = { fe 96 [2] cc b4 [2] ca 81 [2] e4 81 [2] db 9d }

  condition:
    any of them
}