rule TTP_XOR_WriteProcessMemory_a93f {
  strings:
    $key_a93f = { fe 4d [2] cc 6f [2] ca 5a [2] e4 5a [2] db 46 }

  condition:
    any of them
}