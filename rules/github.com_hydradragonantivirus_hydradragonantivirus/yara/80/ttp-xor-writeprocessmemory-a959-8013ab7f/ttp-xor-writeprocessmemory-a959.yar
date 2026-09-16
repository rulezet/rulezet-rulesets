rule TTP_XOR_WriteProcessMemory_a959 {
  strings:
    $key_a959 = { fe 2b [2] cc 09 [2] ca 3c [2] e4 3c [2] db 20 }

  condition:
    any of them
}