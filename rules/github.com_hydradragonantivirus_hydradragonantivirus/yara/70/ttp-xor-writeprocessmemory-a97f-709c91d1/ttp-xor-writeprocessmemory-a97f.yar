rule TTP_XOR_WriteProcessMemory_a97f {
  strings:
    $key_a97f = { fe 0d [2] cc 2f [2] ca 1a [2] e4 1a [2] db 06 }

  condition:
    any of them
}