rule TTP_XOR_WriteProcessMemory_a951 {
  strings:
    $key_a951 = { fe 23 [2] cc 01 [2] ca 34 [2] e4 34 [2] db 28 }

  condition:
    any of them
}