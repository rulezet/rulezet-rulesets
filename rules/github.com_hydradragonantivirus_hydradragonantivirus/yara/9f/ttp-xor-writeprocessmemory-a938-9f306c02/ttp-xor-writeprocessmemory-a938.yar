rule TTP_XOR_WriteProcessMemory_a938 {
  strings:
    $key_a938 = { fe 4a [2] cc 68 [2] ca 5d [2] e4 5d [2] db 41 }

  condition:
    any of them
}