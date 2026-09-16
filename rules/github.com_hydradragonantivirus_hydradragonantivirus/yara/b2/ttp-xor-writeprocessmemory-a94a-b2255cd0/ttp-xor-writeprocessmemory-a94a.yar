rule TTP_XOR_WriteProcessMemory_a94a {
  strings:
    $key_a94a = { fe 38 [2] cc 1a [2] ca 2f [2] e4 2f [2] db 33 }

  condition:
    any of them
}