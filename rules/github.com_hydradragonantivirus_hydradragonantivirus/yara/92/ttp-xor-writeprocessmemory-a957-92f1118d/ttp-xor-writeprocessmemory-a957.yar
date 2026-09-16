rule TTP_XOR_WriteProcessMemory_a957 {
  strings:
    $key_a957 = { fe 25 [2] cc 07 [2] ca 32 [2] e4 32 [2] db 2e }

  condition:
    any of them
}