rule TTP_XOR_WriteProcessMemory_a904 {
  strings:
    $key_a904 = { fe 76 [2] cc 54 [2] ca 61 [2] e4 61 [2] db 7d }

  condition:
    any of them
}