rule TTP_XOR_WriteProcessMemory_a930 {
  strings:
    $key_a930 = { fe 42 [2] cc 60 [2] ca 55 [2] e4 55 [2] db 49 }

  condition:
    any of them
}