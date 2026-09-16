rule TTP_XOR_WriteProcessMemory_a9eb {
  strings:
    $key_a9eb = { fe 99 [2] cc bb [2] ca 8e [2] e4 8e [2] db 92 }

  condition:
    any of them
}