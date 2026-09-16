rule TTP_XOR_WriteProcessMemory_a927 {
  strings:
    $key_a927 = { fe 55 [2] cc 77 [2] ca 42 [2] e4 42 [2] db 5e }

  condition:
    any of them
}