rule TTP_XOR_WriteProcessMemory_a9e8 {
  strings:
    $key_a9e8 = { fe 9a [2] cc b8 [2] ca 8d [2] e4 8d [2] db 91 }

  condition:
    any of them
}