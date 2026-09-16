rule TTP_XOR_WriteProcessMemory_a949 {
  strings:
    $key_a949 = { fe 3b [2] cc 19 [2] ca 2c [2] e4 2c [2] db 30 }

  condition:
    any of them
}