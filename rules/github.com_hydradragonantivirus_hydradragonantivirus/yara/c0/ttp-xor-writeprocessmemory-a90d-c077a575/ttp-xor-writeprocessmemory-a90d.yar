rule TTP_XOR_WriteProcessMemory_a90d {
  strings:
    $key_a90d = { fe 7f [2] cc 5d [2] ca 68 [2] e4 68 [2] db 74 }

  condition:
    any of them
}