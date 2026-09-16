rule TTP_XOR_WriteProcessMemory_a905 {
  strings:
    $key_a905 = { fe 77 [2] cc 55 [2] ca 60 [2] e4 60 [2] db 7c }

  condition:
    any of them
}