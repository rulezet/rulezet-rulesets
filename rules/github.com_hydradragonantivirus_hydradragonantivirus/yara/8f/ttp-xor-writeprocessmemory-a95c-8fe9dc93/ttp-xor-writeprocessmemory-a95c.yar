rule TTP_XOR_WriteProcessMemory_a95c {
  strings:
    $key_a95c = { fe 2e [2] cc 0c [2] ca 39 [2] e4 39 [2] db 25 }

  condition:
    any of them
}