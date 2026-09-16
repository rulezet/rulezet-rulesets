rule TTP_XOR_WriteProcessMemory_a915 {
  strings:
    $key_a915 = { fe 67 [2] cc 45 [2] ca 70 [2] e4 70 [2] db 6c }

  condition:
    any of them
}