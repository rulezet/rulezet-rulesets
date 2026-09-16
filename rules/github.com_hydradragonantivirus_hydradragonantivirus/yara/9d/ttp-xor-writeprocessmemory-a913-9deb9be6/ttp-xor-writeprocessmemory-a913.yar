rule TTP_XOR_WriteProcessMemory_a913 {
  strings:
    $key_a913 = { fe 61 [2] cc 43 [2] ca 76 [2] e4 76 [2] db 6a }

  condition:
    any of them
}