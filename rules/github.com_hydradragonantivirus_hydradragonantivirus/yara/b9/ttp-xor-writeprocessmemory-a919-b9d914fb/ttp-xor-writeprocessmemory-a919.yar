rule TTP_XOR_WriteProcessMemory_a919 {
  strings:
    $key_a919 = { fe 6b [2] cc 49 [2] ca 7c [2] e4 7c [2] db 60 }

  condition:
    any of them
}