rule TTP_XOR_WriteProcessMemory_a9ec {
  strings:
    $key_a9ec = { fe 9e [2] cc bc [2] ca 89 [2] e4 89 [2] db 95 }

  condition:
    any of them
}