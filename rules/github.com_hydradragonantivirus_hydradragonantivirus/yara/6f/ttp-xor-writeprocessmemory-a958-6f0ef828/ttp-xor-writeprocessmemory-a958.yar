rule TTP_XOR_WriteProcessMemory_a958 {
  strings:
    $key_a958 = { fe 2a [2] cc 08 [2] ca 3d [2] e4 3d [2] db 21 }

  condition:
    any of them
}