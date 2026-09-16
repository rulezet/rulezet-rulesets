rule TTP_XOR_WriteProcessMemory_a96f {
  strings:
    $key_a96f = { fe 1d [2] cc 3f [2] ca 0a [2] e4 0a [2] db 16 }

  condition:
    any of them
}