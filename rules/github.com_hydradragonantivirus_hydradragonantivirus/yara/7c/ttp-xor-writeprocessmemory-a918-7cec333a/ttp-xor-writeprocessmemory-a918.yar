rule TTP_XOR_WriteProcessMemory_a918 {
  strings:
    $key_a918 = { fe 6a [2] cc 48 [2] ca 7d [2] e4 7d [2] db 61 }

  condition:
    any of them
}