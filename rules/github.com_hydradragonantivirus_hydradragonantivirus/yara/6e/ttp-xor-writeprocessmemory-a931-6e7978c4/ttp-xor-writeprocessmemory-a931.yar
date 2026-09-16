rule TTP_XOR_WriteProcessMemory_a931 {
  strings:
    $key_a931 = { fe 43 [2] cc 61 [2] ca 54 [2] e4 54 [2] db 48 }

  condition:
    any of them
}