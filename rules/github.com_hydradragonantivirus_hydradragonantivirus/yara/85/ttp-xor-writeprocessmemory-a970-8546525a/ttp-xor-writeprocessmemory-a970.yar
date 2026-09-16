rule TTP_XOR_WriteProcessMemory_a970 {
  strings:
    $key_a970 = { fe 02 [2] cc 20 [2] ca 15 [2] e4 15 [2] db 09 }

  condition:
    any of them
}