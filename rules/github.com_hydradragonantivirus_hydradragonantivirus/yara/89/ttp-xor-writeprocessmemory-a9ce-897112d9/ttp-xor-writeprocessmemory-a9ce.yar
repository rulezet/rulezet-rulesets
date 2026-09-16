rule TTP_XOR_WriteProcessMemory_a9ce {
  strings:
    $key_a9ce = { fe bc [2] cc 9e [2] ca ab [2] e4 ab [2] db b7 }

  condition:
    any of them
}