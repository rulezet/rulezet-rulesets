rule TTP_XOR_WriteProcessMemory_a925 {
  strings:
    $key_a925 = { fe 57 [2] cc 75 [2] ca 40 [2] e4 40 [2] db 5c }

  condition:
    any of them
}