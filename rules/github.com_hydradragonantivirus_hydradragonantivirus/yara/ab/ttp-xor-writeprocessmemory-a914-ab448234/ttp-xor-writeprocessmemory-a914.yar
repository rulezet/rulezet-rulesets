rule TTP_XOR_WriteProcessMemory_a914 {
  strings:
    $key_a914 = { fe 66 [2] cc 44 [2] ca 71 [2] e4 71 [2] db 6d }

  condition:
    any of them
}